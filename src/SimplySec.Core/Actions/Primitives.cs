using System.Text.Json.Nodes;
using SimplySec.Core.Compat;
using SimplySec.Core.Model;

namespace SimplySec.Core.Actions;

// The OS-facing adapters. SimplySec.Windows implements them; tests use fakes.

public interface IFirewallAdapter
{
    List<FirewallRule> FindRules(string name);
    void AddRule(FirewallRule rule);
    void RemoveRulesNamed(string name);
    List<FirewallRule> GroupRules(string group = "SimplySec");
    FirewallProfileState ReadProfile(Profile profile);
    void SetProfile(Profile profile, bool? enabled = null, bool? defaultInboundBlock = null);
    string ExportPolicy(string backupsDir);
}

/// <summary>A registry value before a change: the exact dict stored as the journal's "before".</summary>
public sealed record RegSnapshot(bool KeyExisted, bool Exists, string? Type, JsonNode? Value)
{
    public JsonObject ToJson() => new()
    {
        ["key_existed"] = KeyExisted,
        ["exists"] = Exists,
        ["type"] = Type,
        ["value"] = Value?.DeepClone(),
    };
}

public interface IRegistryAdapter
{
    RegSnapshot Read(string path, string name);
    void Write(string path, string name, JsonNode? value, string vtype);
    void Restore(string path, string name, JsonObject before);
}

public sealed record ServiceState(string Name, bool Exists, string? StartType, bool Delayed, bool Running)
{
    public JsonObject ToJson() => new()
    {
        ["name"] = Name,
        ["exists"] = Exists,
        ["start_type"] = StartType,
        ["delayed"] = Delayed,
        ["running"] = Running,
    };
}

public interface IServicesAdapter
{
    ServiceState Get(string name);
    void SetStartType(string name, string startType, bool delayed = false);
    void Start(string name);
    void Stop(string name);
}

public interface INetworkAdapter
{
    Profile? GetCategory(int index);
    void SetCategory(int index, Profile profile);
}

public interface ISystemAdapter
{
    JsonObject SmbServerGet();
    void SmbServerSet(bool smb1);
    JsonObject DefenderGet();
    void DefenderSetCfa(int mode);
    void UpdateSignatures();
    int NetbiosGet(int configIndex);
    void NetbiosSet(int configIndex, int option);
    void CreateRestorePoint(string description);
}

public sealed record AccountInfo(string Name, bool Enabled);

public interface IAccountsAdapter
{
    AccountInfo? FindByRid(int rid);
    void SetEnabled(string name, bool enabled);
}

public interface IWifiAdapter
{
    string GetConnectionMode(string profileName);
    void SetConnectionMode(string profileName, string mode);
}

public interface ISchedulerAdapter
{
    string? ExportXml(string name);
    void Create(string name, string time);
    bool Exists(string name);
    void Restore(string name, string? xml);
    void Delete(string name);
}

public sealed class Adapters
{
    public required IFirewallAdapter Firewall { get; init; }
    public required IRegistryAdapter Registry { get; init; }
    public required IServicesAdapter Services { get; init; }
    public required INetworkAdapter Network { get; init; }
    public required ISystemAdapter System { get; init; }
    public required IAccountsAdapter Accounts { get; init; }
    public IWifiAdapter? Wifi { get; init; }
    public ISchedulerAdapter? Scheduler { get; init; }
}

public sealed class ActionException(string message) : Exception(message);

/// <summary>One reversible change kind: snapshot, apply, verify, revert, verify the revert.</summary>
public sealed class Primitive
{
    public required string Kind { get; init; }
    public required Func<Adapters, JsonObject, JsonObject> Snapshot { get; init; }
    public required Action<Adapters, JsonObject, JsonObject> Apply { get; init; }
    public required Func<Adapters, JsonObject, bool> Verify { get; init; }
    public required Action<Adapters, JsonObject, JsonObject> Revert { get; init; }
    public required Func<Adapters, JsonObject, JsonObject, bool> VerifyReverted { get; init; }
    public Func<JsonObject, JsonObject, bool> BeforeOk { get; init; } = (_, _) => true;
}

/// <summary>Every change SimplySec makes is one of these primitives.</summary>
public static class Primitives
{
    /// <summary>Services SimplySec may ever change; nothing on the never-touch list (tested).</summary>
    public static readonly HashSet<string> ServiceAllowlist = new(StringComparer.Ordinal)
    {
        "remoteregistry", "tlntsvr", "ftpsvc", "snmp", "ssdpsrv", "upnphost", "lmhosts",
    };

    private static string S(JsonNode? n) => Js.PyRepr(n);

    private static JsonObject Rule(JsonObject p) => p["rule"]!.AsObject();

    private static readonly Primitive FwAdd = new()
    {
        Kind = "firewall.add_rule",
        Snapshot = (a, p) =>
        {
            var name = S(Rule(p)["name"]);
            if (a.Firewall.FindRules(name).Count > 0)
            {
                throw new ActionException($"a rule named '{name}' already exists");
            }
            return new JsonObject { ["existed"] = 0 };
        },
        Apply = (a, p, _) => a.Firewall.AddRule(FirewallRule.FromJson(Rule(p))),
        Verify = (a, p) =>
        {
            var want = Rule(p);
            var rules = a.Firewall.FindRules(S(want["name"]));
            return rules.Count == 1 && rules[0].Enabled && rules[0].Action == S(want["action"]) && rules[0].Direction == S(want["direction"]);
        },
        Revert = (a, p, _) => a.Firewall.RemoveRulesNamed(S(Rule(p)["name"])),
        VerifyReverted = (a, p, _) => a.Firewall.FindRules(S(Rule(p)["name"])).Count == 0,
        BeforeOk = (_, b) => Js.PyEquals(b, new JsonObject { ["existed"] = 0 }),
    };

    private static readonly Primitive FwRemove = new()
    {
        Kind = "firewall.remove_rule",
        Snapshot = (a, p) => new JsonObject
        {
            ["rules"] = new JsonArray(a.Firewall.FindRules(S(p["name"])).Select(r => (JsonNode)r.ToJson()).ToArray()),
        },
        Apply = (a, p, _) => a.Firewall.RemoveRulesNamed(S(p["name"])),
        Verify = (a, p) => a.Firewall.FindRules(S(p["name"])).Count == 0,
        Revert = (a, _, b) =>
        {
            foreach (var d in b["rules"] as JsonArray ?? [])
            {
                a.Firewall.AddRule(FirewallRule.FromJson(d!));
            }
        },
        VerifyReverted = (a, p, b) => a.Firewall.FindRules(S(p["name"])).Count == (b["rules"] as JsonArray ?? []).Count,
        // Undo may only recreate rules with the very name that was removed.
        BeforeOk = (p, b) => (b["rules"] as JsonArray ?? []).All(d => Js.PyEquals(Js.Get(d, "name"), p["name"])),
    };

    private static IEnumerable<string> ProfileKeys(JsonObject p) =>
        new[] { "enabled", "default_inbound_block" }.Where(p.ContainsKey);

    private static JsonObject ProfileSnapshot(Adapters a, JsonObject p)
    {
        var st = a.Firewall.ReadProfile((Profile)Js.Int(p["profile"]));
        return new JsonObject { ["enabled"] = st.Enabled, ["default_inbound_block"] = st.DefaultInboundBlock };
    }

    private static void SetProfile(Adapters a, JsonObject p, JsonObject source)
    {
        bool? enabled = p.ContainsKey("enabled") ? Js.Truthy(source["enabled"]) : null;
        bool? block = p.ContainsKey("default_inbound_block") ? Js.Truthy(source["default_inbound_block"]) : null;
        a.Firewall.SetProfile((Profile)Js.Int(p["profile"]), enabled, block);
    }

    private static readonly Primitive FwProfile = new()
    {
        Kind = "firewall.profile",
        Snapshot = ProfileSnapshot,
        Apply = (a, p, _) => SetProfile(a, p, p),
        Verify = (a, p) =>
        {
            var now = ProfileSnapshot(a, p);
            return ProfileKeys(p).All(k => Js.PyEquals(now[k], p[k]));
        },
        Revert = (a, p, b) => SetProfile(a, p, b),
        VerifyReverted = (a, p, b) =>
        {
            var now = ProfileSnapshot(a, p);
            return ProfileKeys(p).All(k => Js.PyEquals(now[k], b[k]));
        },
        BeforeOk = (p, b) => ProfileKeys(p).All(k => Js.IsBool(Js.Get(b, k))),
    };

    private static readonly Primitive RegValue = new()
    {
        Kind = "registry.value",
        Snapshot = (a, p) => a.Registry.Read(S(p["path"]), S(p["name"])).ToJson(),
        Apply = (a, p, _) => a.Registry.Write(S(p["path"]), S(p["name"]), p["value"], S(p["type"])),
        Verify = (a, p) =>
        {
            var snap = a.Registry.Read(S(p["path"]), S(p["name"]));
            return snap.Exists && Js.PyEquals(snap.Value, p["value"]) && snap.Type == S(p["type"]);
        },
        Revert = (a, p, b) => a.Registry.Restore(S(p["path"]), S(p["name"]), b),
        VerifyReverted = (a, p, b) =>
        {
            var snap = a.Registry.Read(S(p["path"]), S(p["name"]));
            if (!Js.Truthy(b["exists"]))
            {
                return !snap.Exists;
            }
            return snap.Exists && Js.PyEquals(snap.Value, b["value"]);
        },
        BeforeOk = (p, b) =>
        {
            var keys = b.Select(kv => kv.Key).ToHashSet(StringComparer.Ordinal);
            if (!keys.SetEquals(["key_existed", "exists", "type", "value"]))
            {
                return false;
            }
            if (Js.Truthy(b["exists"]))
            {
                // Restoring may only write the same kind of value the fix itself writes.
                return Js.PyEquals(b["type"], p["type"]) && SameKind(b["value"], p["value"]);
            }
            return true;
        },
    };

    private static bool SameKind(JsonNode? a, JsonNode? b)
    {
        if (Js.IsInt(b))
        {
            return Js.IsInt(a);
        }
        if (Js.IsString(b))
        {
            return Js.IsString(a);
        }
        if (b is JsonArray)
        {
            return a is JsonArray;
        }
        return Js.IsBool(b) ? Js.IsBool(a) : false;
    }

    private static readonly Primitive Service = new()
    {
        Kind = "service.start_type",
        Snapshot = (a, p) => a.Services.Get(S(p["name"])).ToJson(),
        Apply = (a, p, b) =>
        {
            a.Services.SetStartType(S(p["name"]), S(p["start_type"]));
            if (S(p["start_type"]) == "disabled" && Js.Truthy(Js.Get(b, "running")))
            {
                a.Services.Stop(S(p["name"]));
            }
        },
        Verify = (a, p) => a.Services.Get(S(p["name"])).StartType == S(p["start_type"]),
        Revert = (a, p, b) =>
        {
            a.Services.SetStartType(S(p["name"]), S(b["start_type"]), Js.Truthy(Js.Get(b, "delayed")));
            if (Js.Truthy(Js.Get(b, "running")) && !a.Services.Get(S(p["name"])).Running)
            {
                a.Services.Start(S(p["name"]));
            }
        },
        VerifyReverted = (a, p, b) => a.Services.Get(S(p["name"])).StartType == S(b["start_type"]),
        BeforeOk = (p, b) => S(Js.Get(b, "start_type")) is "auto" or "manual" or "disabled" && Js.PyEquals(Js.Get(b, "name"), p["name"]),
    };

    private static string? CatName(Profile? p) => p switch
    {
        Profile.Private => "Private",
        Profile.Public => "Public",
        _ => null,
    };

    private static Profile ParseProfileName(string s) => PyStr.Upper(s) switch
    {
        "PRIVATE" => Profile.Private,
        "PUBLIC" => Profile.Public,
        "DOMAIN" => Profile.Domain,
        _ => throw new KeyNotFoundException(s),
    };

    private static readonly Primitive NetCategory = new()
    {
        Kind = "network.category",
        Snapshot = (a, p) => new JsonObject { ["profile"] = CatName(a.Network.GetCategory(Js.Int(p["index"]))) },
        Apply = (a, p, _) => a.Network.SetCategory(Js.Int(p["index"]), ParseProfileName(S(p["profile"]))),
        Verify = (a, p) => CatName(a.Network.GetCategory(Js.Int(p["index"]))) == S(p["profile"]),
        Revert = (a, p, b) => a.Network.SetCategory(Js.Int(p["index"]), ParseProfileName(S(b["profile"]))),
        VerifyReverted = (a, p, b) => CatName(a.Network.GetCategory(Js.Int(p["index"]))) == Js.StrOrNull(b["profile"]),
        BeforeOk = (_, b) => Js.IsString(Js.Get(b, "profile")) && S(b["profile"]) is "Private" or "Public",
    };

    private static readonly Primitive WifiMode = new()
    {
        Kind = "wifi.connection_mode",
        Snapshot = (a, p) => new JsonObject { ["mode"] = a.Wifi!.GetConnectionMode(S(p["profile_name"])) },
        Apply = (a, p, _) => a.Wifi!.SetConnectionMode(S(p["profile_name"]), S(p["mode"])),
        Verify = (a, p) => a.Wifi!.GetConnectionMode(S(p["profile_name"])) == S(p["mode"]),
        Revert = (a, p, b) => a.Wifi!.SetConnectionMode(S(p["profile_name"]), S(b["mode"])),
        VerifyReverted = (a, p, b) => a.Wifi!.GetConnectionMode(S(p["profile_name"])) == S(b["mode"]),
        BeforeOk = (_, b) => Js.IsString(Js.Get(b, "mode")) && S(b["mode"]) is "auto" or "manual",
    };

    private static readonly Primitive Task = new()
    {
        Kind = "task.schedule",
        Snapshot = (a, p) => new JsonObject { ["xml"] = a.Scheduler!.ExportXml(S(p["name"])) },
        Apply = (a, p, _) => a.Scheduler!.Create(S(p["name"]), S(p["time"])),
        Verify = (a, p) => a.Scheduler!.Exists(S(p["name"])),
        Revert = (a, p, b) => a.Scheduler!.Restore(S(p["name"]), Js.StrOrNull(Js.Get(b, "xml"))),
        VerifyReverted = (a, p, b) => a.Scheduler!.Exists(S(p["name"])) == Js.Truthy(Js.Get(b, "xml")),
        BeforeOk = (_, b) => Js.IsNull(Js.Get(b, "xml")) || S(Js.Get(b, "xml")).Contains("SimplySec", StringComparison.Ordinal),
    };

    private static readonly Primitive Smb = new()
    {
        Kind = "smb.server_setting",
        Snapshot = (a, _) => new JsonObject { ["smb1"] = Js.Truthy(a.System.SmbServerGet()["smb1"]) },
        Apply = (a, p, _) => a.System.SmbServerSet(Js.Truthy(p["smb1"])),
        Verify = (a, p) => Js.Truthy(a.System.SmbServerGet()["smb1"]) == Js.Truthy(p["smb1"]),
        Revert = (a, _, b) => a.System.SmbServerSet(Js.Truthy(b["smb1"])),
        VerifyReverted = (a, _, b) => Js.Truthy(a.System.SmbServerGet()["smb1"]) == Js.Truthy(b["smb1"]),
        BeforeOk = (_, b) => Js.IsBool(Js.Get(b, "smb1")),
    };

    private static bool OneOf012(JsonNode? n) => Js.NumEquals(n, 0) || Js.NumEquals(n, 1) || Js.NumEquals(n, 2);

    private static readonly Primitive DefenderPref = new()
    {
        Kind = "defender.pref",
        Snapshot = (a, _) => new JsonObject { ["controlled_folder_access"] = Js.Int(a.System.DefenderGet()["controlled_folder_access"]) },
        Apply = (a, p, _) => a.System.DefenderSetCfa(Js.Int(p["controlled_folder_access"])),
        Verify = (a, p) => Js.Int(a.System.DefenderGet()["controlled_folder_access"]) == Js.Int(p["controlled_folder_access"]),
        Revert = (a, _, b) => a.System.DefenderSetCfa(Js.Int(b["controlled_folder_access"])),
        VerifyReverted = (a, _, b) => Js.Int(a.System.DefenderGet()["controlled_folder_access"]) == Js.Int(b["controlled_folder_access"]),
        BeforeOk = (_, b) => OneOf012(Js.Get(b, "controlled_folder_access")),
    };

    private static readonly Primitive DefenderUpdate = new()
    {
        Kind = "defender.update_signatures",
        Snapshot = (_, _) => [],
        Apply = (a, _, _) => a.System.UpdateSignatures(),
        Verify = (_, _) => true,
        Revert = (_, _, _) => { }, // downloading definitions has nothing to undo
        VerifyReverted = (_, _, _) => true,
        BeforeOk = (_, b) => b.Count == 0,
    };

    private static readonly Primitive Netbios = new()
    {
        Kind = "netbios.adapter",
        Snapshot = (a, p) => new JsonObject { ["option"] = a.System.NetbiosGet(Js.Int(p["config_index"])) },
        Apply = (a, p, _) => a.System.NetbiosSet(Js.Int(p["config_index"]), Js.Int(p["option"])),
        Verify = (a, p) => a.System.NetbiosGet(Js.Int(p["config_index"])) == Js.Int(p["option"]),
        Revert = (a, p, b) => a.System.NetbiosSet(Js.Int(p["config_index"]), Js.Int(b["option"])),
        VerifyReverted = (a, p, b) => a.System.NetbiosGet(Js.Int(p["config_index"])) == Js.Int(b["option"]),
        BeforeOk = (_, b) => OneOf012(Js.Get(b, "option")),
    };

    private static JsonObject AccountSnapshot(Adapters a, JsonObject p)
    {
        var acct = a.Accounts.FindByRid(Js.Int(p["rid"])) ?? throw new ActionException($"no local account with RID {S(p["rid"])}");
        return new JsonObject { ["name"] = acct.Name, ["enabled"] = acct.Enabled };
    }

    private static readonly Primitive Account = new()
    {
        Kind = "account.enabled",
        Snapshot = AccountSnapshot,
        Apply = (a, p, b) => a.Accounts.SetEnabled(S(b["name"]), Js.Truthy(p["enabled"])),
        Verify = (a, p) => Js.Truthy(AccountSnapshot(a, p)["enabled"]) == Js.Truthy(p["enabled"]),
        Revert = (a, _, b) => a.Accounts.SetEnabled(S(b["name"]), Js.Truthy(b["enabled"])),
        VerifyReverted = (a, p, b) => Js.Truthy(AccountSnapshot(a, p)["enabled"]) == Js.Truthy(b["enabled"]),
        BeforeOk = (_, b) => Js.IsBool(Js.Get(b, "enabled")) && Js.IsString(Js.Get(b, "name")),
    };

    public static readonly IReadOnlyDictionary<string, Primitive> All =
        new[] { FwAdd, FwRemove, FwProfile, RegValue, Service, NetCategory, WifiMode, Task, Smb, DefenderPref, DefenderUpdate, Netbios, Account }
            .ToDictionary(p => p.Kind, StringComparer.Ordinal);
}
