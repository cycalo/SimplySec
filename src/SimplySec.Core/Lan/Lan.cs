using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
using SimplySec.Core.Checks;
using SimplySec.Core.Compat;
using SimplySec.Core.Knowledge;
using SimplySec.Core.Model;
using static SimplySec.Core.Checks.CheckHelpers;

namespace SimplySec.Core.Lan;

/// <summary>Who is this device? MAC vendor (OUI), randomized MACs.</summary>
public static class Identify
{
    public static string NormalizeMac(string? mac)
    {
        var hexes = new string(PyStr.Upper(mac).Where(c => "0123456789ABCDEF".Contains(c)).ToArray());
        if (hexes.Length != 12)
        {
            return "";
        }
        return string.Join(':', Enumerable.Range(0, 6).Select(i => hexes.Substring(i * 2, 2)));
    }

    private static int FirstOctet(string m) => Convert.ToInt32(m[..2], 16);

    /// <summary>Locally administered bit set: a private (randomized) address, typical for phones.</summary>
    public static bool IsRandomized(string? mac)
    {
        var m = NormalizeMac(mac);
        return m.Length > 0 && (FirstOctet(m) & 0x02) != 0;
    }

    public static bool IsMulticast(string? mac)
    {
        var m = NormalizeMac(mac);
        return m.Length > 0 && (FirstOctet(m) & 0x01) != 0;
    }

    public static string Describe(string mac, string vendor, string name)
    {
        if (name.Length > 0)
        {
            return name;
        }
        if (vendor.Length > 0)
        {
            return $"{vendor} device";
        }
        if (IsRandomized(mac))
        {
            return "Device with a private address (likely a phone or tablet)";
        }
        return "Unknown device";
    }
}

public sealed class OuiDatabase(Dictionary<string, string> entries)
{
    public Dictionary<string, string> Entries { get; } = entries;

    private static readonly Lazy<OuiDatabase> Bundled = new(() =>
    {
        using var stream = typeof(OuiDatabase).Assembly.GetManifestResourceStream("resources/oui.csv.gz");
        return stream is null ? new OuiDatabase([]) : FromGzipCsv(stream);
    });

    public static OuiDatabase Default => Bundled.Value;

    /// <summary>Rows "AABBCC,Vendor" (CSV, vendor may be quoted).</summary>
    public static OuiDatabase FromGzipCsv(Stream gz)
    {
        using var unzip = new GZipStream(gz, CompressionMode.Decompress);
        using var reader = new StreamReader(unzip, Encoding.UTF8);
        var entries = new Dictionary<string, string>(StringComparer.Ordinal);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            var row = Csv.Split(line);
            if (row.Count >= 2)
            {
                entries[row[0]] = row[1];
            }
        }
        return new OuiDatabase(entries);
    }

    /// <summary>nmap's nmap-mac-prefixes: 'AABBCC Vendor Name' lines.</summary>
    public static OuiDatabase FromNmap(string text)
    {
        var entries = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in text.Split('\n'))
        {
            var l = line.TrimEnd('\r');
            if (l.Length > 7 && !l.StartsWith('#'))
            {
                var sp = l.IndexOf(' ');
                var prefix = sp >= 0 ? l[..sp] : l;
                var vendor = sp >= 0 ? l[(sp + 1)..] : "";
                if (prefix.Length == 6)
                {
                    entries[PyStr.Upper(prefix)] = PyStr.Strip(vendor);
                }
            }
        }
        return new OuiDatabase(entries);
    }

    public string Vendor(string? mac)
    {
        var m = Identify.NormalizeMac(mac);
        if (m.Length == 0 || Identify.IsRandomized(m))
        {
            return "";
        }
        return Entries.TryGetValue(m.Replace(":", "", StringComparison.Ordinal)[..6], out var v) ? v : "";
    }
}

/// <summary>Minimal CSV splitter (Python csv.reader default dialect).</summary>
internal static class Csv
{
    public static List<string> Split(string line)
    {
        var output = new List<string>();
        var sb = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (quoted)
            {
                if (c == '"' && i + 1 < line.Length && line[i + 1] == '"')
                {
                    sb.Append('"');
                    i++;
                }
                else if (c == '"')
                {
                    quoted = false;
                }
                else
                {
                    sb.Append(c);
                }
            }
            else if (c == '"')
            {
                quoted = true;
            }
            else if (c == ',')
            {
                output.Add(sb.ToString());
                sb.Clear();
            }
            else
            {
                sb.Append(c);
            }
        }
        output.Add(sb.ToString());
        return output;
    }
}

/// <summary>A device on a confirmed home network.</summary>
public sealed class Device
{
    public string Ip { get; set; } = "";
    public string Mac { get; set; } = "";
    public string Vendor { get; set; } = "";
    public string Hostname { get; set; } = "";
    public string SsdpName { get; set; } = "";
    public string Model { get; set; } = "";
    public List<int> OpenPorts { get; set; } = [];
    public bool IsGateway { get; set; }
    public string FirstSeen { get; set; } = "";
    public string LastSeen { get; set; } = "";
    public bool Trusted { get; set; }
    public string Label { get; set; } = "";
    public bool New { get; set; }
    /// <summary>nmap deep scan results.</summary>
    public List<JsonObject> Services { get; set; } = [];

    public string Name => Label.Length > 0 ? Label : SsdpName.Length > 0 ? SsdpName : Hostname;
    public string Display => $"{Identify.Describe(Mac, Vendor, Name)} ({Ip})";
    public bool Randomized => Identify.IsRandomized(Mac);

    public JsonObject ToJson() => new()
    {
        ["ip"] = Ip,
        ["mac"] = Mac,
        ["vendor"] = Vendor,
        ["hostname"] = Hostname,
        ["ssdp_name"] = SsdpName,
        ["model"] = Model,
        ["open_ports"] = new JsonArray(OpenPorts.Select(p => (JsonNode)p).ToArray()),
        ["is_gateway"] = IsGateway,
        ["first_seen"] = FirstSeen,
        ["last_seen"] = LastSeen,
        ["trusted"] = Trusted,
        ["label"] = Label,
        ["new"] = New,
        ["services"] = new JsonArray(Services.Select(s => s.DeepClone()).ToArray()),
        ["name"] = Name,
        ["randomized"] = Randomized,
    };
}

/// <summary>Device inventory findings and router findings (guidance only).</summary>
public static class Inventory
{
    public const string AreaLan = "Home network";
    public const string AreaRouter = "Router";

    /// <summary>Open ports on another device that deserve attention (LAN exposure: one level lower).</summary>
    public static List<(int Port, string Name, Severity Sev)> RiskyServices(Device device, KnowledgeBase kb)
    {
        var output = new List<(int, string, Severity)>();
        foreach (var port in device.OpenPorts.Order())
        {
            var info = kb.Port("tcp", port);
            if (info is null)
            {
                continue;
            }
            if (device.IsGateway && port is 53 or 80 or 443 or 8080 or 8443)
            {
                continue; // the router's own admin page and DNS are expected
            }
            var sev = info.Risk.Shifted(-1);
            if (sev >= Severity.Medium)
            {
                output.Add((port, info.Name, sev));
            }
        }
        return output;
    }

    public static List<Finding> DeviceFindings(List<Device> devices, KnowledgeBase kb, bool firstScan)
    {
        var output = new List<Finding>();
        foreach (var d in devices)
        {
            var risky = RiskyServices(d, kb);
            if (risky.Count > 0)
            {
                var sev = risky.Max(r => r.Sev);
                var names = string.Join(", ", risky.Select(r => $"{r.Name} ({r.Port})"));
                var infos = risky.Select(r => kb.Port("tcp", r.Port)).ToList();
                var details = risky.Zip(infos).Select(x => ($"Port {x.First.Port}", $"{x.First.Name}: {(x.Second is not null ? x.Second.Explain : "")}")).ToList();
                details.Add(("MAC", d.Mac));
                details.Add(("Vendor", d.Vendor.Length > 0 ? d.Vendor : "unknown"));
                var advice = string.Join(" ", infos.Where(i => i is not null).Select(i => i!.Advice));
                output.Add(NewFinding($"lan.services.{d.Mac}", "lan", AreaLan, $"{d.Display} offers {names}", sev,
                    "Another device on your network accepts connections on services that are often attacked. SimplySec doesn't change other devices; check its settings or app, update its firmware, set a strong password, or turn the service off.",
                    details, learnMore: advice));
            }
            if (d.New && !d.Trusted && !firstScan)
            {
                output.Add(NewFinding($"lan.new_device.{d.Mac}", "lan", AreaLan, $"New device on your network: {d.Display}", Severity.Low,
                    "SimplySec hasn't seen this device before. If you don't recognise it, check your router's device list and change your Wi-Fi password. Mark it as trusted on the My network page if it's yours.",
                    [("MAC", d.Mac), ("Vendor", d.Vendor.Length > 0 ? d.Vendor : "unknown"), ("First seen", d.FirstSeen)]));
            }
        }
        return output;
    }

    private static string UrlHost(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var u))
        {
            return PyStr.Lower(u.Host.Trim('[', ']'));
        }
        return "";
    }

    public static List<Finding> RouterFindings(JsonObject router, HashSet<string> thisPcIps, Dictionary<string, int> accepted)
    {
        var output = new List<Finding>();
        if (!Js.Truthy(Js.Get(router, "found")))
        {
            var nf = NewFinding("router.upnp_not_found", "router", AreaRouter, "Your router does not offer UPnP port forwarding", Severity.Info,
                "Programs on your network can't open ports on your router by themselves. That's the safer setting.");
            nf.Status = FindingStatus.Info;
            return [nf];
        }
        var name = Js.Truthy(Js.Get(router, "friendly_name")) ? S(router["friendly_name"])
            : Js.Truthy(Js.Get(router, "model")) ? S(router["model"]) : "Your router";
        var host = UrlHost(S(GetOr(router, "location", JsonValue.Create(""))));
        var admin = host.Length > 0 ? $"http://{host}" : "the address printed on your router's sticker";
        var steps = $"Open your router's admin page ({admin}) in a browser and sign in with the admin password from the sticker. Look under Advanced, NAT, Port forwarding or UPnP. ";
        foreach (var m in GetOr(router, "mappings", new JsonArray()) as JsonArray ?? [])
        {
            if (!Js.Truthy(GetOr(m, "enabled", JsonValue.Create(true))))
            {
                continue;
            }
            var client = Js.Get(m, "internal_client");
            var toMe = Js.IsString(client) && thisPcIps.Contains(client!.GetValue<string>());
            var desc = Js.Truthy(Js.Get(m, "description")) ? S(m!["description"]) : "no description";
            var key = $"router.forward.{S(Js.Get(m, "protocol"))}.{S(Js.Get(m, "external_port"))}";
            var f = NewFinding(key, "router", AreaRouter,
                toMe
                    ? $"Your router forwards internet port {S(Js.Get(m, "protocol"))} {S(Js.Get(m, "external_port"))} to this PC"
                    : $"Your router forwards internet port {S(Js.Get(m, "protocol"))} {S(Js.Get(m, "external_port"))} to {S(client)}",
                toMe ? Severity.Critical : Severity.High,
                "Anyone on the internet can connect through your router to " + (toMe ? "this PC" : "that device") +
                $" on port {S(Js.Get(m, "internal_port"))} ('{desc}'). Programs (often games or remote-access tools) open these with UPnP. If you don't need it, close the program or turn UPnP off in your router.",
                [
                    ("Internal", $"{S(client)}:{S(Js.Get(m, "internal_port"))}"),
                    ("Description", desc),
                    ("Lease", Js.Truthy(Js.Get(m, "lease")) ? $"{S(Js.Get(m, "lease"))} s" : "permanent"),
                    ("Router", name),
                ],
                learnMore: $"First check which program opened it: '{desc}'. If you don't need it, close that program or turn off its 'open port'/UPnP option; UPnP forwards usually disappear when the program stops. " +
                           steps + "Delete the forward there, or turn UPnP off. Choose Keep if you need it (for example a game server).");
            f.KeepKey = $"keep:{key}";
            f.Width = 1;
            if (accepted.ContainsKey(f.KeepKey))
            {
                f.Status = FindingStatus.Accepted;
            }
            output.Add(f);
        }
        output.Add(NewFinding("router.upnp_on", "router", AreaRouter, $"UPnP is on in {name}", Severity.Low,
            "UPnP lets any program on your network open ports on your router to the internet, without asking. Games and video calls sometimes use it. If nothing needs it, turn UPnP off in your router's admin page (usually under Advanced or NAT).",
            [("Router", PyStr.Strip($"{name} {S(GetOr(router, "model", JsonValue.Create("")))}")), ("Description", S(GetOr(router, "location", JsonValue.Create(""))))],
            learnMore: steps + "Turn UPnP off. If a game or video-call app then has connection problems, turn it back on."));
        if (Js.Truthy(Js.Get(router, "external_is_private")))
        {
            var f = NewFinding("router.cgnat", "router", AreaRouter, "Your internet provider shares your public address (CGNAT)", Severity.Info,
                $"Your router's internet address ({S(Js.Get(router, "external_ip"))}) is a private one, so your provider blocks connections from the internet before they reach your router. Port forwards won't work from outside, which is safer.");
            f.Status = FindingStatus.Info;
            output.Add(f);
        }
        return output;
    }
}
