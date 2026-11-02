using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using SimplySec.Windows.Interop;

// Usage: SimplySec.Spikes firewall|sockets|sigs <paths-file>
var mode = args.Length > 0 ? args[0] : "firewall";
var sw = Stopwatch.StartNew();
JsonNode output;
switch (mode)
{
    case "firewall":
    {
        var policy = FirewallCom.CreatePolicy();
        var rules = new JsonArray();
        foreach (var o in FirewallCom.Enumerate(policy.get_Rules()))
        {
            var r = (INetFwRule3)o;
            rules.Add(new JsonObject
            {
                ["name"] = r.get_Name(),
                ["application"] = r.get_ApplicationName() ?? "",
                ["service"] = r.get_serviceName() ?? "",
                ["protocol"] = r.get_Protocol(),
                ["local_ports"] = r.get_LocalPorts() ?? "*",
                ["remote_addresses"] = r.get_RemoteAddresses() ?? "*",
                ["direction"] = r.get_Direction() == 1 ? "in" : "out",
                ["enabled"] = r.get_Enabled(),
                ["profiles"] = r.get_Profiles(),
                ["action"] = r.get_Action() == 1 ? "allow" : "block",
                ["local_user_owner"] = r.get_LocalUserOwner() ?? "",
                ["edge_traversal_options"] = r.get_EdgeTraversalOptions(),
            });
        }
        var profiles = new JsonArray();
        foreach (var p in new[] { 1, 2, 4 })
        {
            profiles.Add(new JsonObject
            {
                ["profile"] = p,
                ["enabled"] = policy.get_FirewallEnabled(p),
                ["default_inbound_block"] = policy.get_DefaultInboundAction(p) == 0,
                ["block_all_inbound"] = policy.get_BlockAllInboundTraffic(p),
            });
        }
        output = new JsonObject { ["profiles"] = profiles, ["rules"] = rules, ["current_profiles"] = policy.get_CurrentProfileTypes() };
        break;
    }
    case "sockets":
    {
        var arr = new JsonArray();
        var seen = new HashSet<(string, string, int)>();
        foreach (var s in IpHelper.AllSockets())
        {
            if (s.Protocol == "tcp" && s.State != IpHelper.MibTcpStateListen) continue;
            if (!seen.Add((s.Protocol, s.LocalIp, s.LocalPort))) continue;
            arr.Add(new JsonObject { ["protocol"] = s.Protocol, ["address"] = s.LocalIp, ["port"] = s.LocalPort, ["pid"] = s.Pid });
        }
        output = arr;
        break;
    }
    case "sigs":
    {
        var obj = new JsonObject();
        foreach (var path in File.ReadAllLines(args[1]))
        {
            if (path.Length == 0) continue;
            var r = WinTrust.Verify(path);
            obj[path.ToLowerInvariant()] = new JsonObject { ["status"] = r.Status, ["signer"] = r.Signer };
        }
        output = obj;
        break;
    }
    default:
        throw new ArgumentException(mode);
}
Console.Error.WriteLine($"{mode}: {sw.ElapsedMilliseconds} ms");
Console.WriteLine(output.ToJsonString(new JsonSerializerOptions { WriteIndented = false }));
