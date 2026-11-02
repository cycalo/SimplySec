using System.Security;
using System.Text;
using System.Text.Json.Nodes;
using SimplySec.Core.Compat;

namespace SimplySec.Core.Lan;

public sealed class PortMapping
{
    public int ExternalPort { get; set; }
    public string Protocol { get; set; } = "";
    public string InternalClient { get; set; } = "";
    public int InternalPort { get; set; }
    public string Description { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public string RemoteHost { get; set; } = "";
    public int Lease { get; set; }

    public JsonObject ToJson() => new()
    {
        ["external_port"] = ExternalPort,
        ["protocol"] = Protocol,
        ["internal_client"] = InternalClient,
        ["internal_port"] = InternalPort,
        ["description"] = Description,
        ["enabled"] = Enabled,
        ["remote_host"] = RemoteHost,
        ["lease"] = Lease,
    };
}

public sealed class RouterInfo
{
    public bool Found { get; set; }
    public string Location { get; set; } = "";
    public string FriendlyName { get; set; } = "";
    public string Manufacturer { get; set; } = "";
    public string Model { get; set; } = "";
    public string ServiceType { get; set; } = "";
    public string ControlUrl { get; set; } = "";
    public string ExternalIp { get; set; } = "";
    public List<PortMapping> Mappings { get; } = [];
    public string Error { get; set; } = "";

    private static readonly IpNet Cgnat = PyIp.TryParseNetwork("100.64.0.0/10", out var n) ? n : default;

    public bool ExternalIsPrivate =>
        PyIp.TryParseAddress(ExternalIp, out var ip) && (ip.IsPrivate || PyIp.Contains(Cgnat, ip));

    public JsonObject ToJson() => new()
    {
        ["found"] = Found,
        ["location"] = Location,
        ["friendly_name"] = FriendlyName,
        ["manufacturer"] = Manufacturer,
        ["model"] = Model,
        ["service_type"] = ServiceType,
        ["control_url"] = ControlUrl,
        ["external_ip"] = ExternalIp,
        ["mappings"] = new JsonArray(Mappings.Select(m => (JsonNode)m.ToJson()).ToArray()),
        ["error"] = Error,
        ["external_is_private"] = ExternalIsPrivate,
    };
}

public sealed class SoapFault(string code, string description = "") : Exception(PyStr.Strip($"UPnP error {code} {description}"))
{
    public string Code { get; } = code;
}

/// <summary>
/// Read the router's UPnP Internet Gateway Device: external IP and port forwards (read-only).
/// SSDP finds it, then SOAP GetExternalIPAddress and GetGenericPortMappingEntry (≤ 256, stop at 713).
/// </summary>
public static class UpnpIgd
{
    public static readonly string[] IgdTypes =
    [
        "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    ];

    public static readonly string[] WanServices =
    [
        "urn:schemas-upnp-org:service:WANIPConnection:2",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
    ];

    public const int MaxEntries = 256;

    /// <summary>(serviceType, absolute controlURL) of the first WAN connection service.</summary>
    public static (string, string) FindWanService(byte[] descriptionXml, string baseUrl)
    {
        var root = Ssdp.ParseXml(descriptionXml);
        var urlBase = "";
        foreach (var el in Ssdp.Iter(root))
        {
            var t = Ssdp.Text(el);
            if (el.Name.LocalName.EndsWith("URLBase", StringComparison.Ordinal) && !string.IsNullOrEmpty(t))
            {
                urlBase = PyStr.Strip(t);
            }
        }
        foreach (var svc in Ssdp.Iter(root))
        {
            if (!svc.Name.LocalName.EndsWith("service", StringComparison.Ordinal))
            {
                continue;
            }
            string stype = "", control = "";
            foreach (var child in svc.Elements())
            {
                var t = Ssdp.Text(child);
                if (child.Name.LocalName.EndsWith("serviceType", StringComparison.Ordinal) && !string.IsNullOrEmpty(t))
                {
                    stype = PyStr.Strip(t);
                }
                else if (child.Name.LocalName.EndsWith("controlURL", StringComparison.Ordinal) && !string.IsNullOrEmpty(t))
                {
                    control = PyStr.Strip(t);
                }
            }
            if (WanServices.Contains(stype) && control.Length > 0)
            {
                return (stype, UrlJoin(urlBase.Length > 0 ? urlBase : baseUrl, control));
            }
        }
        return ("", "");
    }

    public static string UrlJoin(string baseUrl, string relative) =>
        Uri.TryCreate(new Uri(baseUrl), relative, out var u) ? u.ToString() : relative;

    public static byte[] SoapEnvelope(string serviceType, string action, IEnumerable<(string Key, string Value)>? args = null)
    {
        var body = string.Concat((args ?? []).Select(kv => $"<{kv.Key}>{Escape(kv.Value)}</{kv.Key}>"));
        return Encoding.UTF8.GetBytes(
            "<?xml version=\"1.0\"?>" +
            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
            "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" +
            $"<s:Body><u:{action} xmlns:u=\"{Escape(serviceType)}\">{body}</u:{action}></s:Body></s:Envelope>");
    }

    /// <summary>xml.sax.saxutils.escape: &amp;, &lt;, &gt; only.</summary>
    private static string Escape(string s) =>
        s.Replace("&", "&amp;", StringComparison.Ordinal).Replace(">", "&gt;", StringComparison.Ordinal).Replace("<", "&lt;", StringComparison.Ordinal);

    /// <summary>The action response's out-arguments, or a SoapFault.</summary>
    public static Dictionary<string, string> ParseSoap(byte[] body)
    {
        var root = Ssdp.ParseXml(body);
        foreach (var el in Ssdp.Iter(root))
        {
            if (el.Name.LocalName.EndsWith("UPnPError", StringComparison.Ordinal))
            {
                string code = "", desc = "";
                foreach (var c in el.Elements())
                {
                    if (c.Name.LocalName.EndsWith("errorCode", StringComparison.Ordinal))
                    {
                        code = PyStr.Strip(Ssdp.Text(c));
                    }
                    else if (c.Name.LocalName.EndsWith("errorDescription", StringComparison.Ordinal))
                    {
                        desc = PyStr.Strip(Ssdp.Text(c));
                    }
                }
                throw new SoapFault(code, desc);
            }
        }
        foreach (var el in Ssdp.Iter(root))
        {
            if (el.Name.LocalName.EndsWith("Body", StringComparison.Ordinal))
            {
                foreach (var resp in el.Elements())
                {
                    var output = new Dictionary<string, string>(StringComparer.Ordinal);
                    foreach (var child in resp.Elements())
                    {
                        output[child.Name.LocalName] = PyStr.Strip(Ssdp.Text(child));
                    }
                    return output;
                }
            }
        }
        return [];
    }

    public static Dictionary<string, string> Call(ISsdp ssdp, string controlUrl, string serviceType, string action,
        IEnumerable<(string, string)>? args = null, List<IpNet>? allowed = null)
    {
        var (status, body) = ssdp.Fetch(controlUrl, allowed, data: SoapEnvelope(serviceType, action, args),
            headers: new Dictionary<string, string>
            {
                ["Content-Type"] = "text/xml; charset=\"utf-8\"",
                ["SOAPAction"] = $"\"{serviceType}#{action}\"",
            });
        var output = ParseSoap(body);
        if (status >= 400 && output.Count == 0)
        {
            throw new SoapFault(status.ToString(System.Globalization.CultureInfo.InvariantCulture), "HTTP error");
        }
        return output;
    }

    public static PortMapping MappingFrom(Dictionary<string, string> values)
    {
        int Num(string key)
        {
            var v = values.GetValueOrDefault(key, "0");
            if (string.IsNullOrEmpty(v))
            {
                return 0;
            }
            return PyIp.TryPyInt(v, out var n) ? n : 0;
        }
        var desc = values.GetValueOrDefault("NewPortMappingDescription", "");
        return new PortMapping
        {
            ExternalPort = Num("NewExternalPort"),
            Protocol = PyStr.Upper(values.GetValueOrDefault("NewProtocol", "")),
            InternalClient = values.GetValueOrDefault("NewInternalClient", ""),
            InternalPort = Num("NewInternalPort"),
            Description = desc.Length > 120 ? desc[..120] : desc,
            Enabled = values.GetValueOrDefault("NewEnabled", "1") is "1" or "true" or "True",
            RemoteHost = values.GetValueOrDefault("NewRemoteHost", ""),
            Lease = Num("NewLeaseDuration"),
        };
    }

    public static RouterInfo ReadRouter(ISsdp ssdp, List<string> gateways, List<IpNet> allowed, double timeout = 3.0)
    {
        var info = new RouterInfo();
        var responses = new List<SsdpResponse>();
        foreach (var st in IgdTypes)
        {
            responses = ssdp.Search(st, timeout).Where(r => gateways.Count == 0 || gateways.Contains(r.Ip)).ToList();
            if (responses.Count > 0)
            {
                break;
            }
        }
        if (responses.Count == 0)
        {
            return info;
        }
        var resp = responses[0];
        info.Found = true;
        info.Location = resp.Location;
        try
        {
            var (_, desc) = ssdp.Fetch(resp.Location, allowed);
            (info.FriendlyName, info.Manufacturer, info.Model) = Ssdp.DeviceName(desc);
            (info.ServiceType, info.ControlUrl) = FindWanService(desc, resp.Location);
            if (info.ControlUrl.Length == 0)
            {
                info.Error = "the router describes no WAN connection service";
                return info;
            }
            info.ExternalIp = Call(ssdp, info.ControlUrl, info.ServiceType, "GetExternalIPAddress", allowed: allowed)
                .GetValueOrDefault("NewExternalIPAddress", "");
            for (var index = 0; index < MaxEntries; index++)
            {
                Dictionary<string, string> values;
                try
                {
                    values = Call(ssdp, info.ControlUrl, info.ServiceType, "GetGenericPortMappingEntry",
                        [("NewPortMappingIndex", index.ToString(System.Globalization.CultureInfo.InvariantCulture))], allowed);
                }
                catch (SoapFault fault)
                {
                    if (fault.Code is not ("713" or "714" or "402"))
                    {
                        info.Error = fault.Message;
                    }
                    break;
                }
                info.Mappings.Add(MappingFrom(values));
            }
        }
        catch (Exception exc) when (exc is not OutOfMemoryException)
        {
            info.Error = exc.Message;
        }
        return info;
    }

    internal static string XmlEscapeAttr(string s) => SecurityElement.Escape(s);
}
