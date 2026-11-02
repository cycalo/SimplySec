using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using SimplySec.Core.Checks;
using SimplySec.Core.Compat;
using SimplySec.Core.Engine;
using SimplySec.Core.Knowledge;
using SimplySec.Core.Model;
using SimplySec.Core.Storage;

namespace SimplySec.Core.Lan;

/// <summary>A network that may be scanned (only after the user confirms it is theirs).</summary>
public sealed record ScanTarget(string Interface, int InterfaceIndex, string NetworkName, string LocalIp, IpNet Network, IReadOnlyList<string> Gateways)
{
    /// <summary>How a confirmation is remembered: the network's name and subnet.</summary>
    public string Key => $"{(NetworkName.Length > 0 ? NetworkName : Interface)}|{Network}";

    public string Label => $"{(NetworkName.Length > 0 ? NetworkName : Interface)} ({Network}, via {Interface})";
}

public sealed record NmapService(int Port, string Protocol, string State, string Name, string Product, string Version)
{
    public JsonObject ToJson() => new()
    {
        ["port"] = Port, ["protocol"] = Protocol, ["state"] = State, ["name"] = Name, ["product"] = Product, ["version"] = Version,
    };
}

public sealed record NmapHost(string Ip, string Mac, string Vendor, string Hostname, List<NmapService> Services);

/// <summary>The OS parts of a network scan (neighbour table, optional nmap), provided by SimplySec.Windows.</summary>
public interface ILanHost
{
    Dictionary<string, string> Neighbors(int interfaceIndex);
    List<NmapHost> NmapScan(List<string> ips, List<int> ports);
    OuiDatabase Oui { get; }
    ISsdp Ssdp { get; }
}

/// <summary>Which networks may be scanned, and async TCP discovery of the devices on them.</summary>
public static class Discovery
{
    public const int MaxPrefix = 22;
    public static readonly int[] DiscoveryPorts = [80, 443, 445, 22, 139, 554, 8080, 62078, 8008, 9100];

    public static List<ScanTarget> ScanTargets(IEnumerable<NetInterface> interfaces)
    {
        var output = new List<ScanTarget>();
        foreach (var iface in interfaces)
        {
            if (!iface.Up || iface.Kind is not (InterfaceKind.Ethernet or InterfaceKind.Wifi))
            {
                continue;
            }
            foreach (var ipi in iface.IpInterfaces())
            {
                if (ipi.Family != 4 || !ipi.Ip.IsPrivate || ipi.Ip.IsLoopback || ipi.Ip.IsLinkLocal)
                {
                    continue;
                }
                var net = ipi.Network;
                if (net.Prefix < MaxPrefix)
                {
                    PyIp.TryParseNetwork($"{ipi.Ip}/{MaxPrefix}", out net);
                }
                if (net.Prefix >= 31)
                {
                    continue;
                }
                output.Add(new ScanTarget(iface.Alias, iface.Index, iface.NetworkName, ipi.Ip.ToString(), net,
                    iface.Gateways.Where(g => g.Contains('.')).ToList()));
            }
        }
        return output;
    }

    public static List<string> HostsOf(ScanTarget target)
    {
        var net = target.Network;
        var output = new List<string>();
        for (var v = net.Network + 1; v < net.Broadcast; v++)
        {
            var ip = PyIp.Format(4, v);
            if (ip != target.LocalIp)
            {
                output.Add(ip);
            }
        }
        return output;
    }

    /// <summary>True: open; false: refused (host is up); null: no answer.</summary>
    private static async Task<bool?> Probe(string ip, int port, TimeSpan timeout, SemaphoreSlim sem)
    {
        await sem.WaitAsync().ConfigureAwait(false);
        try
        {
            using var sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            using var cts = new CancellationTokenSource(timeout);
            try
            {
                await sock.ConnectAsync(IPAddress.Parse(ip), port, cts.Token).ConfigureAwait(false);
                return true;
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionRefused)
            {
                return false;
            }
            catch (Exception e) when (e is SocketException or OperationCanceledException)
            {
                return null;
            }
        }
        finally
        {
            sem.Release();
        }
    }

    /// <summary>Map of host → open ports, for every host that answered at all.</summary>
    public static Dictionary<string, HashSet<int>> Sweep(List<string> hosts, IEnumerable<int> ports, double timeout = 0.6, int concurrency = 256)
    {
        var portList = ports.ToList();
        var sem = new SemaphoreSlim(concurrency);
        var t = TimeSpan.FromSeconds(timeout);
        var tasks = hosts.SelectMany(h => portList.Select(p => (h, p, Task.Run(() => Probe(h, p, t, sem))))).ToList();
        Task.WaitAll(tasks.Select(x => (Task)x.Item3).ToArray());
        var alive = new Dictionary<string, HashSet<int>>(StringComparer.Ordinal);
        foreach (var (h, p, task) in tasks)
        {
            var r = task.Result;
            if (r is null)
            {
                continue;
            }
            if (!alive.TryGetValue(h, out var set))
            {
                set = [];
                alive[h] = set;
            }
            if (r == true)
            {
                set.Add(p);
            }
        }
        return alive;
    }
}

/// <summary>Home-network scan: devices, their services, the router (UPnP), only on confirmed networks.</summary>
public static class LanScan
{
    public const string OwnedKey = "owned_networks";

    public static JsonObject OwnedNetworks(History history) =>
        history.GetSetting(OwnedKey) is JsonObject o && o.Count > 0 ? (JsonObject)o.DeepClone() : [];

    public static bool IsOwned(History history, ScanTarget target) => OwnedNetworks(history).ContainsKey(target.Key);

    public static void SetOwned(History history, ScanTarget target, bool owned)
    {
        var nets = OwnedNetworks(history);
        if (owned)
        {
            nets[target.Key] = new JsonObject { ["label"] = target.Label, ["confirmed"] = PyTime.NowIsoSeconds() };
        }
        else
        {
            nets.Remove(target.Key);
        }
        history.SetSetting(OwnedKey, nets);
    }

    public static void ForgetNetwork(History history, string key)
    {
        var nets = OwnedNetworks(history);
        nets.Remove(key);
        history.SetSetting(OwnedKey, nets);
    }

    public static bool InTarget(ScanTarget target, string ip) =>
        PyIp.TryParseAddress(ip, out var a) && PyIp.Contains(target.Network, a);

    private static Dictionary<string, string> ReverseDns(List<string> ips, double timeout = 2.0)
    {
        var output = new Dictionary<string, string>(StringComparer.Ordinal);
        var tasks = ips.Select(ip => (ip, Task.Run(async () =>
        {
            try
            {
                return (await Dns.GetHostEntryAsync(IPAddress.Parse(ip)).ConfigureAwait(false)).HostName;
            }
            catch (Exception)
            {
                return "";
            }
        }))).ToList();
        Task.WaitAll(tasks.Select(t => (Task)t.Item2).ToArray(), TimeSpan.FromSeconds(timeout + 3));
        foreach (var (ip, task) in tasks)
        {
            if (task.IsCompletedSuccessfully && task.Result.Length > 0 && task.Result != ip)
            {
                output[ip] = task.Result;
            }
        }
        return output;
    }

    private static Dictionary<string, (string Friendly, string Model)> SsdpNames(ISsdp ssdp, ScanTarget target)
    {
        var names = new Dictionary<string, (string, string)>(StringComparer.Ordinal);
        List<SsdpResponse> responses;
        try
        {
            responses = ssdp.Search("ssdp:all", 3, target.LocalIp);
        }
        catch (SocketException)
        {
            return names;
        }
        foreach (var r in responses)
        {
            if (names.ContainsKey(r.Ip) || !InTarget(target, r.Ip))
            {
                continue;
            }
            try
            {
                var (_, body) = ssdp.Fetch(r.Location, [target.Network], 3);
                var (friendly, maker, model) = Ssdp.DeviceName(body);
                if (friendly.Length > 0 || model.Length > 0)
                {
                    names[r.Ip] = (friendly, string.Join(" ", new[] { maker, model }.Where(x => x.Length > 0)));
                }
            }
            catch (Exception)
            {
            }
        }
        return names;
    }

    /// <summary>Scan the confirmed networks and merge devices, router info and findings into the result.</summary>
    public static ScanResult ScanNetwork(ScanEngine engine, ILanHost host, ScanResult result, List<ScanTarget>? targets = null,
        Action<string>? progress = null, bool deep = false)
    {
        var kb = KnowledgeBase.Get();
        var history = engine.History;
        var say = progress ?? (_ => { });
        var candidates = targets ?? Discovery.ScanTargets(result.Interfaces);
        var owned = candidates.Where(t => IsOwned(history, t)).ToList();
        var knownBefore = history.Devices().Select(d => Js.Str(d["mac"])).ToHashSet(StringComparer.Ordinal);
        var thisPcIps = result.Interfaces.SelectMany(i => i.IpInterfaces()).Select(i => i.Ip.ToString()).ToHashSet(StringComparer.Ordinal);
        var devices = new List<Device>();
        var routers = new List<JsonObject>();
        var probePorts = kb.LanProbePorts().Select(p => p.Port).ToList();

        foreach (var target in owned)
        {
            say($"Looking for devices on {target.Label}…");
            var alive = Discovery.Sweep(Discovery.HostsOf(target), Discovery.DiscoveryPorts);
            Dictionary<string, string> neigh;
            try
            {
                neigh = host.Neighbors(target.InterfaceIndex)
                    .Where(kv => InTarget(target, kv.Key) && !Identify.IsMulticast(kv.Value))
                    .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);
            }
            catch (Exception)
            {
                neigh = [];
            }
            var ips = alive.Keys.Union(neigh.Keys).Where(ip => ip != target.LocalIp)
                .OrderBy(s => s, Comparer<string>.Create(CompareDotted)).ToList();
            say(Progress.MarkDone($"Found {ips.Count} device(s) on {target.Network}"));
            say($"Checking which services {ips.Count} device(s) offer…");
            var openMap = Discovery.Sweep(ips, probePorts, 0.8);
            say(Progress.MarkDone($"Checked {probePorts.Count} services on each device"));
            say("Identifying devices (vendor, name)…");
            var rdns = ReverseDns(ips);
            var names = SsdpNames(host.Ssdp, target);
            var deepMap = new Dictionary<string, NmapHost>(StringComparer.Ordinal);
            if (deep)
            {
                say("Deep scan with nmap (this can take a few minutes)…");
                try
                {
                    foreach (var h in host.NmapScan(ips, probePorts))
                    {
                        deepMap[h.Ip] = h;
                    }
                }
                catch (Exception)
                {
                }
            }
            foreach (var ip in ips)
            {
                var mac = Identify.NormalizeMac(neigh.GetValueOrDefault(ip, ""));
                var (friendly, model) = names.GetValueOrDefault(ip, ("", ""));
                var ports = new HashSet<int>(openMap.GetValueOrDefault(ip) ?? []);
                ports.UnionWith(alive.GetValueOrDefault(ip) ?? []);
                var d = new Device
                {
                    Ip = ip,
                    Mac = mac,
                    Vendor = host.Oui.Vendor(mac),
                    Hostname = rdns.GetValueOrDefault(ip, ""),
                    SsdpName = friendly,
                    Model = model,
                    OpenPorts = ports.Order().ToList(),
                    IsGateway = target.Gateways.Contains(ip),
                };
                if (deepMap.TryGetValue(ip, out var nh))
                {
                    d.Services = nh.Services.Select(s => s.ToJson()).ToList();
                    d.Vendor = d.Vendor.Length > 0 ? d.Vendor : nh.Vendor;
                }
                devices.Add(d);
            }
            say(Progress.MarkDone("Identified devices"));
            say("Reading your router's port forwards (UPnP)…");
            routers.Add(UpnpIgd.ReadRouter(host.Ssdp, [.. target.Gateways], [target.Network]).ToJson());
            say(Progress.MarkDone("Read the router"));
        }

        // Inventory: remember devices by MAC; flag new ones after the first network scan.
        var firstScan = knownBefore.Count == 0;
        foreach (var d in devices.Where(d => d.Mac.Length > 0))
        {
            d.New = history.UpsertDevice(d.Mac, d.Ip, d.Name, d.Vendor,
                new JsonObject { ["open_ports"] = new JsonArray(d.OpenPorts.Select(p => (JsonNode)p).ToArray()), ["model"] = d.Model });
        }
        var stored = history.Devices().ToDictionary(x => Js.Str(x["mac"]), StringComparer.Ordinal);
        foreach (var d in devices)
        {
            var rec = stored.GetValueOrDefault(d.Mac) ?? [];
            d.FirstSeen = Js.Str(Js.Get(rec, "first_seen"));
            d.LastSeen = Js.Str(Js.Get(rec, "last_seen"));
            d.Trusted = Js.Truthy(Js.Get(rec, "trusted"));
            d.Label = Js.Truthy(Js.Get(rec, "label")) ? Js.Str(rec["label"]) : "";
        }

        var findings = Inventory.DeviceFindings(devices, kb, firstScan);
        var accepted = history.AcceptedWidths();
        foreach (var r in routers)
        {
            findings.AddRange(Inventory.RouterFindings(r, thisPcIps, accepted));
        }
        result.Findings = result.Findings.Where(f => f.Check is not ("lan" or "router")).Concat(findings)
            .OrderBy(f => f.Status != FindingStatus.Open).ThenBy(f => -(int)f.Severity)
            .ThenBy(f => f.Area, StringComparer.Ordinal).ThenBy(f => f.Title, StringComparer.Ordinal).ToList();
        result.Score = Scoring.Score(result.Findings);
        result.Grade = Scoring.Grade(result.Score, result.Findings);
        result.Extras["devices"] = new JsonArray(devices.Select(d => (JsonNode)d.ToJson()).ToArray());
        result.Extras["router"] = routers.Count > 0 ? routers[0] : new JsonObject();
        result.Extras["networks"] = Js.StrArray(owned.Select(t => t.Label));
        return result;
    }

    private static int CompareDotted(string a, string b)
    {
        var pa = a.Split('.').Select(x => int.Parse(x, CultureInfo.InvariantCulture)).ToArray();
        var pb = b.Split('.').Select(x => int.Parse(x, CultureInfo.InvariantCulture)).ToArray();
        for (var i = 0; i < Math.Min(pa.Length, pb.Length); i++)
        {
            var c = pa[i].CompareTo(pb[i]);
            if (c != 0)
            {
                return c;
            }
        }
        return pa.Length.CompareTo(pb.Length);
    }
}
