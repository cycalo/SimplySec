using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using SimplySec.Core.Compat;

namespace SimplySec.Core.Lan;

public sealed class UnsafeUrlException(string message) : ArgumentException(message);

public sealed record SsdpResponse(string Ip, string Location, string St, string Server = "", string Usn = "");

/// <summary>SSDP discovery and fetching of LAN URLs, mockable for tests.</summary>
public interface ISsdp
{
    List<SsdpResponse> Search(string st = "ssdp:all", double timeout = 3.0, string bindIp = "");
    (int Status, byte[] Body) Fetch(string url, List<IpNet>? allowed, double timeout = 4, byte[]? data = null, Dictionary<string, string>? headers = null);
}

/// <summary>
/// SSDP (UPnP discovery) and safe fetching of device description XML. Safety: DTDs rejected,
/// 256 KB response cap, and only http URLs that point at a private address on the scanned network.
/// </summary>
public sealed class Ssdp : ISsdp
{
    public const int MaxBytes = 256 * 1024;
    public static readonly Ssdp Instance = new();

    public static void CheckLanUrl(string url, List<IpNet>? allowed = null)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme != "http" || string.IsNullOrEmpty(u.Host))
        {
            throw new UnsafeUrlException($"only plain http URLs on the local network are fetched: {url}");
        }
        var host = u.Host.Trim('[', ']');
        if (!PyIp.TryParseAddress(host, out var ip))
        {
            throw new UnsafeUrlException($"host must be an IP address: {url}");
        }
        if (!ip.IsPrivate || ip.IsLoopback)
        {
            throw new UnsafeUrlException($"not a local network address: {url}");
        }
        if (allowed is not null && !allowed.Any(n => PyIp.Contains(n, ip)))
        {
            throw new UnsafeUrlException($"outside the scanned network: {url}");
        }
    }

    public (int Status, byte[] Body) Fetch(string url, List<IpNet>? allowed, double timeout = 4, byte[]? data = null, Dictionary<string, string>? headers = null)
    {
        CheckLanUrl(url, allowed);
        using var handler = new HttpClientHandler { AllowAutoRedirect = false, UseProxy = false, UseCookies = false };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(timeout) };
        using var req = new HttpRequestMessage(data is null ? HttpMethod.Get : HttpMethod.Post, url);
        if (data is not null)
        {
            req.Content = new ByteArrayContent(data);
        }
        foreach (var (k, v) in headers ?? [])
        {
            if (k.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
            {
                req.Content?.Headers.TryAddWithoutValidation(k, v);
            }
            else
            {
                req.Headers.TryAddWithoutValidation(k, v);
            }
        }
        using var resp = client.Send(req, HttpCompletionOption.ResponseHeadersRead);
        using var stream = resp.Content.ReadAsStream();
        var buffer = new byte[MaxBytes + 1];
        var total = 0;
        int n;
        while (total < buffer.Length && (n = stream.Read(buffer, total, buffer.Length - total)) > 0)
        {
            total += n;
        }
        if (total > MaxBytes)
        {
            throw new InvalidDataException($"response from {url} is larger than {MaxBytes / 1024} KB");
        }
        return ((int)resp.StatusCode, buffer[..total]);
    }

    /// <summary>Parse XML with DTDs, entity expansion and external resolution rejected.</summary>
    public static XElement ParseXml(byte[] body)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersFromEntities = 0,
        };
        using var ms = new MemoryStream(body);
        using var reader = XmlReader.Create(ms, settings);
        return XElement.Load(reader);
    }

    /// <summary>ElementTree's <c>el.text</c>: the text before the first child element.</summary>
    public static string? Text(XElement el)
    {
        var sb = new StringBuilder();
        var any = false;
        foreach (var node in el.Nodes())
        {
            if (node is XElement)
            {
                break;
            }
            if (node is XText t)
            {
                sb.Append(t.Value);
                any = true;
            }
        }
        return any ? sb.ToString() : null;
    }

    /// <summary>ElementTree's root.iter(): the root and all descendants in document order.</summary>
    public static IEnumerable<XElement> Iter(XElement root) => root.DescendantsAndSelf();

    public static SsdpResponse? ParseResponse(byte[] data, string ip)
    {
        var text = Encoding.UTF8.GetString(data);
        var lines = text.Split("\r\n");
        if (lines.Length == 0 || (!lines[0].Contains("200", StringComparison.Ordinal) && !PyStr.Upper(lines[0]).StartsWith("NOTIFY", StringComparison.Ordinal)))
        {
            return null;
        }
        var headers = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in lines.Skip(1))
        {
            var colon = line.IndexOf(':');
            if (colon >= 0)
            {
                headers[PyStr.Lower(PyStr.Strip(line[..colon]))] = PyStr.Strip(line[(colon + 1)..]);
            }
        }
        var loc = headers.GetValueOrDefault("location", "");
        if (loc.Length == 0)
        {
            return null;
        }
        return new SsdpResponse(ip, loc, headers.GetValueOrDefault("st", headers.GetValueOrDefault("nt", "")),
            headers.GetValueOrDefault("server", ""), headers.GetValueOrDefault("usn", ""));
    }

    /// <summary>Send one M-SEARCH and collect responses until the timeout.</summary>
    public List<SsdpResponse> Search(string st = "ssdp:all", double timeout = 3.0, string bindIp = "")
    {
        var msg = Encoding.ASCII.GetBytes(
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n" + $"ST: {st}\r\n\r\n");
        var output = new List<SsdpResponse>();
        using var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        sock.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 2);
        if (bindIp.Length > 0)
        {
            var bind = IPAddress.Parse(bindIp);
            sock.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, bind.GetAddressBytes());
            sock.Bind(new IPEndPoint(bind, 0));
        }
        sock.ReceiveTimeout = 500;
        sock.SendTo(msg, new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900));
        var sw = Stopwatch.StartNew();
        var buffer = new byte[8192];
        while (sw.Elapsed.TotalSeconds < timeout)
        {
            EndPoint from = new IPEndPoint(IPAddress.Any, 0);
            int n;
            try
            {
                n = sock.ReceiveFrom(buffer, ref from);
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.TimedOut)
            {
                continue;
            }
            catch (SocketException)
            {
                break;
            }
            var resp = ParseResponse(buffer[..n], ((IPEndPoint)from).Address.ToString());
            if (resp is not null && output.All(r => r.Location != resp.Location))
            {
                output.Add(resp);
            }
        }
        return output;
    }

    /// <summary>(friendlyName, manufacturer, modelName) from a UPnP device description.</summary>
    public static (string Friendly, string Maker, string Model) DeviceName(byte[] xmlBody)
    {
        var root = ParseXml(xmlBody);
        string First(string tag)
        {
            foreach (var el in Iter(root))
            {
                var t = Text(el);
                if (el.Name.LocalName.EndsWith(tag, StringComparison.Ordinal) && !string.IsNullOrEmpty(t))
                {
                    var s = PyStr.Strip(t);
                    return s.Length > 120 ? s[..120] : s;
                }
            }
            return "";
        }
        return (First("friendlyName"), First("manufacturer"), First("modelName"));
    }
}
