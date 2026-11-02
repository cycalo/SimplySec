using System.Text.Json.Nodes;
using SimplySec.Core.Compat;

namespace SimplySec.Core.Model;

// Plain data shared by every layer. Each type maps to and from the exact JSON shape that
// Python v2 writes (to_dict/from_dict), so scans, the journal and history stay compatible.

public sealed class NetInterface
{
    public int Index { get; set; }
    public string Alias { get; set; } = "";
    public string Description { get; set; } = "";
    public InterfaceKind Kind { get; set; } = InterfaceKind.Ethernet;
    public string Mac { get; set; } = "";
    public bool Up { get; set; } = true;
    public List<string> Addresses { get; set; } = [];
    /// <summary>Null: Windows has no connection profile for it.</summary>
    public Profile? Profile { get; set; }
    public string NetworkName { get; set; } = "";
    public List<string> Gateways { get; set; } = [];
    public List<string> DnsServers { get; set; } = [];
    public List<string> DhcpServers { get; set; } = [];

    /// <summary>Windows treats unidentified networks as Public.</summary>
    public Profile EffectiveProfile => Profile ?? Model.Profile.Public;

    public List<IpIface> IpInterfaces()
    {
        var output = new List<IpIface>();
        foreach (var text in Addresses)
        {
            var pct = text.IndexOf('%');
            if (PyIp.TryParseInterface(pct >= 0 ? text[..pct] : text, out var ii))
            {
                output.Add(ii);
            }
        }
        return output;
    }

    public bool HasIp(string ip)
    {
        var pct = ip.IndexOf('%');
        if (!PyIp.TryParseAddress(pct >= 0 ? ip[..pct] : ip, out var target))
        {
            return false;
        }
        return IpInterfaces().Any(i => i.Ip.Family == target.Family && i.Ip.Value == target.Value && i.Ip.Scope == target.Scope);
    }

    public NetInterface Clone()
    {
        var c = (NetInterface)MemberwiseClone();
        c.Addresses = [.. Addresses];
        c.Gateways = [.. Gateways];
        c.DnsServers = [.. DnsServers];
        c.DhcpServers = [.. DhcpServers];
        return c;
    }

    public JsonObject ToJson() => new()
    {
        ["index"] = Index,
        ["alias"] = Alias,
        ["description"] = Description,
        ["kind"] = Kind.Value(),
        ["mac"] = Mac,
        ["up"] = Up,
        ["addresses"] = Js.StrArray(Addresses),
        ["profile"] = Profile is null ? null : (int)Profile.Value,
        ["network_name"] = NetworkName,
        ["gateways"] = Js.StrArray(Gateways),
        ["dns_servers"] = Js.StrArray(DnsServers),
        ["dhcp_servers"] = Js.StrArray(DhcpServers),
    };

    public static NetInterface FromJson(JsonNode d)
    {
        var prof = Js.Get(d, "profile");
        return new NetInterface
        {
            Index = Js.Int(Js.Get(d, "index")),
            Alias = Js.Str(Js.Get(d, "alias")),
            Description = Js.Str(Js.Get(d, "description")),
            Kind = EnumText.ParseKind(Js.Str(Js.Get(d, "kind"), "ethernet")),
            Mac = Js.Str(Js.Get(d, "mac")),
            Up = Js.Bool(Js.Get(d, "up"), true),
            Addresses = Js.StrList(Js.Get(d, "addresses")),
            Profile = Js.IsNull(prof) ? null : (Profile)Js.Int(prof),
            NetworkName = Js.Str(Js.Get(d, "network_name")),
            Gateways = Js.StrList(Js.Get(d, "gateways")),
            DnsServers = Js.StrList(Js.Get(d, "dns_servers")),
            DhcpServers = Js.StrList(Js.Get(d, "dhcp_servers")),
        };
    }
}

public sealed class Listener
{
    public string Protocol { get; set; } = "tcp";
    public string Address { get; set; } = "";
    public int Port { get; set; }
    public int Pid { get; set; }
    public string Process { get; set; } = "";
    public string Exe { get; set; } = "";
    /// <summary>Null: unknown.</summary>
    public List<string>? Services { get; set; } = [];
    /// <summary>Null: unknown (token unreadable).</summary>
    public string? UserSid { get; set; }
    /// <summary>"": not an AppContainer; null: unknown.</summary>
    public string? PackageSid { get; set; } = "";

    public string Key => $"{Protocol}:{Address}:{Port}";

    private IpAddr? ParsedAddress
    {
        get
        {
            var pct = Address.IndexOf('%');
            return PyIp.ParseAddress(pct >= 0 ? Address[..pct] : Address);
        }
    }

    public int Family => ParsedAddress?.Family ?? 4;

    public bool IsLoopback => ParsedAddress?.IsLoopback ?? false;

    public bool IsWildcard => Address is "0.0.0.0" or "::" or "";

    public Listener Clone()
    {
        var c = (Listener)MemberwiseClone();
        c.Services = Services is null ? null : [.. Services];
        return c;
    }

    public JsonObject ToJson() => new()
    {
        ["protocol"] = Protocol,
        ["address"] = Address,
        ["port"] = Port,
        ["pid"] = Pid,
        ["process"] = Process,
        ["exe"] = Exe,
        ["services"] = Services is null ? null : Js.StrArray(Services),
        ["user_sid"] = UserSid,
        ["package_sid"] = PackageSid,
    };

    public static Listener FromJson(JsonNode d) => new()
    {
        Protocol = Js.Str(Js.Get(d, "protocol")),
        Address = Js.Str(Js.Get(d, "address")),
        Port = Js.Int(Js.Get(d, "port")),
        Pid = Js.Int(Js.Get(d, "pid")),
        Process = Js.Str(Js.Get(d, "process")),
        Exe = Js.Str(Js.Get(d, "exe")),
        Services = Js.Has(d, "services") ? Js.StrListOrNull(Js.Get(d, "services")) : [],
        UserSid = Js.StrOrNull(Js.Get(d, "user_sid")),
        PackageSid = Js.Has(d, "package_sid") ? Js.StrOrNull(Js.Get(d, "package_sid")) : "",
    };
}

public sealed class FirewallProfileState
{
    public Profile Profile { get; set; }
    public bool Enabled { get; set; } = true;
    public bool DefaultInboundBlock { get; set; } = true;
    public bool BlockAllInbound { get; set; }

    public FirewallProfileState Clone() => (FirewallProfileState)MemberwiseClone();

    public JsonObject ToJson() => new()
    {
        ["profile"] = (int)Profile,
        ["enabled"] = Enabled,
        ["default_inbound_block"] = DefaultInboundBlock,
        ["block_all_inbound"] = BlockAllInbound,
    };

    public static FirewallProfileState FromJson(JsonNode d) => new()
    {
        Profile = (Profile)Js.Int(Js.Get(d, "profile")),
        Enabled = Js.Bool(Js.Get(d, "enabled")),
        DefaultInboundBlock = Js.Bool(Js.Get(d, "default_inbound_block")),
        BlockAllInbound = Js.Bool(Js.Get(d, "block_all_inbound")),
    };
}

public sealed class FirewallRule
{
    public string Name { get; set; } = "";
    public string Action { get; set; } = "allow";
    public string Direction { get; set; } = "in";
    public bool Enabled { get; set; } = true;
    public int Protocol { get; set; } = 256;
    public string LocalPorts { get; set; } = "*";
    public string RemotePorts { get; set; } = "*";
    public string LocalAddresses { get; set; } = "*";
    public string RemoteAddresses { get; set; } = "*";
    public string Application { get; set; } = "";
    public string Service { get; set; } = "";
    public int Profiles { get; set; } = EnumText.AllProfilesMask;
    public string InterfaceTypes { get; set; } = "All";
    public List<string> Interfaces { get; set; } = [];
    public bool EdgeTraversal { get; set; }
    public int EdgeTraversalOptions { get; set; }
    public string Grouping { get; set; } = "";
    public string Description { get; set; } = "";
    public string LocalUserAuthorized { get; set; } = "";
    public string LocalUserOwner { get; set; } = "";
    public string LocalAppPackageId { get; set; } = "";
    public string RemoteUserAuthorized { get; set; } = "";
    public string RemoteMachineAuthorized { get; set; } = "";
    public int SecureFlags { get; set; }
    public string IcmpTypes { get; set; } = "";
    /// <summary>Hidden trust-tuple keyword conditions (TTK) read from the registry.</summary>
    public List<string> TrustTuples { get; set; } = [];

    public string ProtocolLabel => Protocol switch
    {
        6 => "TCP",
        17 => "UDP",
        256 => "Any",
        1 => "ICMPv4",
        58 => "ICMPv6",
        _ => Protocol.ToString(System.Globalization.CultureInfo.InvariantCulture),
    };

    public int ProfileMask => Profiles == EnumText.AllProfilesMask ? 7 : Profiles & 7;

    public FirewallRule Clone()
    {
        var c = (FirewallRule)MemberwiseClone();
        c.Interfaces = [.. Interfaces];
        c.TrustTuples = [.. TrustTuples];
        return c;
    }

    public JsonObject ToJson() => new()
    {
        ["name"] = Name,
        ["action"] = Action,
        ["direction"] = Direction,
        ["enabled"] = Enabled,
        ["protocol"] = Protocol,
        ["local_ports"] = LocalPorts,
        ["remote_ports"] = RemotePorts,
        ["local_addresses"] = LocalAddresses,
        ["remote_addresses"] = RemoteAddresses,
        ["application"] = Application,
        ["service"] = Service,
        ["profiles"] = Profiles,
        ["interface_types"] = InterfaceTypes,
        ["interfaces"] = Js.StrArray(Interfaces),
        ["edge_traversal"] = EdgeTraversal,
        ["edge_traversal_options"] = EdgeTraversalOptions,
        ["grouping"] = Grouping,
        ["description"] = Description,
        ["local_user_authorized"] = LocalUserAuthorized,
        ["local_user_owner"] = LocalUserOwner,
        ["local_app_package_id"] = LocalAppPackageId,
        ["remote_user_authorized"] = RemoteUserAuthorized,
        ["remote_machine_authorized"] = RemoteMachineAuthorized,
        ["secure_flags"] = SecureFlags,
        ["icmp_types"] = IcmpTypes,
        ["trust_tuples"] = Js.StrArray(TrustTuples),
    };

    /// <summary>Lenient: unknown keys are ignored, missing keys take the defaults.</summary>
    public static FirewallRule FromJson(JsonNode d)
    {
        var r = new FirewallRule();
        if (d is not JsonObject o)
        {
            return r;
        }
        foreach (var (k, v) in o)
        {
            switch (k)
            {
                case "name": r.Name = Js.Str(v); break;
                case "action": r.Action = Js.Str(v); break;
                case "direction": r.Direction = Js.Str(v); break;
                case "enabled": r.Enabled = Js.Bool(v); break;
                case "protocol": r.Protocol = Js.Int(v); break;
                case "local_ports": r.LocalPorts = Js.Str(v); break;
                case "remote_ports": r.RemotePorts = Js.Str(v); break;
                case "local_addresses": r.LocalAddresses = Js.Str(v); break;
                case "remote_addresses": r.RemoteAddresses = Js.Str(v); break;
                case "application": r.Application = Js.Str(v); break;
                case "service": r.Service = Js.Str(v); break;
                case "profiles": r.Profiles = Js.Int(v); break;
                case "interface_types": r.InterfaceTypes = Js.Str(v); break;
                case "interfaces": r.Interfaces = Js.StrList(v); break;
                case "edge_traversal": r.EdgeTraversal = Js.Bool(v); break;
                case "edge_traversal_options": r.EdgeTraversalOptions = Js.Int(v); break;
                case "grouping": r.Grouping = Js.Str(v); break;
                case "description": r.Description = Js.Str(v); break;
                case "local_user_authorized": r.LocalUserAuthorized = Js.Str(v); break;
                case "local_user_owner": r.LocalUserOwner = Js.Str(v); break;
                case "local_app_package_id": r.LocalAppPackageId = Js.Str(v); break;
                case "remote_user_authorized": r.RemoteUserAuthorized = Js.Str(v); break;
                case "remote_machine_authorized": r.RemoteMachineAuthorized = Js.Str(v); break;
                case "secure_flags": r.SecureFlags = Js.Int(v); break;
                case "icmp_types": r.IcmpTypes = Js.Str(v); break;
                case "trust_tuples": r.TrustTuples = Js.StrList(v); break;
            }
        }
        return r;
    }
}

public sealed class FirewallState
{
    public OrderedDictionary<Profile, FirewallProfileState> Profiles { get; set; } = [];
    public List<FirewallRule> Rules { get; set; } = [];
    public int CurrentProfiles { get; set; }
    public bool ManagedByPolicy { get; set; }
    public int LocalPolicyModifyState { get; set; }

    public FirewallState Clone()
    {
        var c = (FirewallState)MemberwiseClone();
        c.Profiles = [];
        foreach (var (k, v) in Profiles)
        {
            c.Profiles.Add(k, v.Clone());
        }
        c.Rules = Rules.Select(r => r.Clone()).ToList();
        return c;
    }

    public JsonObject ToJson() => new()
    {
        ["profiles"] = new JsonArray(Profiles.Values.Select(p => (JsonNode)p.ToJson()).ToArray()),
        ["rules"] = new JsonArray(Rules.Select(r => (JsonNode)r.ToJson()).ToArray()),
        ["current_profiles"] = CurrentProfiles,
        ["managed_by_policy"] = ManagedByPolicy,
        ["local_policy_modify_state"] = LocalPolicyModifyState,
    };

    public static FirewallState FromJson(JsonNode d)
    {
        var fw = new FirewallState();
        foreach (var p in Js.Get(d, "profiles")?.AsArray() ?? [])
        {
            var st = FirewallProfileState.FromJson(p!);
            fw.Profiles[st.Profile] = st;
        }
        fw.Rules = (Js.Get(d, "rules") as JsonArray ?? []).Select(r => FirewallRule.FromJson(r!)).ToList();
        fw.CurrentProfiles = Js.Int(Js.Get(d, "current_profiles"));
        fw.ManagedByPolicy = Js.Bool(Js.Get(d, "managed_by_policy"));
        fw.LocalPolicyModifyState = Js.Int(Js.Get(d, "local_policy_modify_state"));
        return fw;
    }
}

public sealed class InterfaceExposure
{
    public string Interface { get; set; } = "";
    public InterfaceKind InterfaceKind { get; set; }
    public Profile Profile { get; set; }
    public bool ProfileAssumed { get; set; }
    public Verdict Verdict { get; set; }
    public Scope Scope { get; set; }
    public List<string> Remote { get; set; } = [];
    public List<string> AllowRules { get; set; } = [];
    public List<string> BlockRules { get; set; } = [];
    public List<string> UncertainRules { get; set; } = [];
    public bool EdgeTraversal { get; set; }
    public string Reason { get; set; } = "";

    public JsonObject ToJson() => new()
    {
        ["interface"] = Interface,
        ["interface_kind"] = InterfaceKind.Value(),
        ["profile"] = (int)Profile,
        ["profile_assumed"] = ProfileAssumed,
        ["verdict"] = Verdict.Value(),
        ["scope"] = Scope.Value(),
        ["remote"] = Js.StrArray(Remote),
        ["allow_rules"] = Js.StrArray(AllowRules),
        ["block_rules"] = Js.StrArray(BlockRules),
        ["uncertain_rules"] = Js.StrArray(UncertainRules),
        ["edge_traversal"] = EdgeTraversal,
        ["reason"] = Reason,
    };

    public static InterfaceExposure FromJson(JsonNode d) => new()
    {
        Interface = Js.Str(Js.Get(d, "interface")),
        InterfaceKind = EnumText.ParseKind(Js.Str(Js.Get(d, "interface_kind"))),
        Profile = (Profile)Js.Int(Js.Get(d, "profile")),
        ProfileAssumed = Js.Bool(Js.Get(d, "profile_assumed")),
        Verdict = EnumText.ParseVerdict(Js.Str(Js.Get(d, "verdict"))),
        Scope = EnumText.ParseScope(Js.Str(Js.Get(d, "scope"))),
        Remote = Js.StrList(Js.Get(d, "remote")),
        AllowRules = Js.StrList(Js.Get(d, "allow_rules")),
        BlockRules = Js.StrList(Js.Get(d, "block_rules")),
        UncertainRules = Js.StrList(Js.Get(d, "uncertain_rules")),
        EdgeTraversal = Js.Bool(Js.Get(d, "edge_traversal")),
        Reason = Js.Str(Js.Get(d, "reason")),
    };
}

public sealed class Exposure
{
    public required Listener Listener { get; set; }
    public Verdict Verdict { get; set; }
    public Scope Scope { get; set; } = Scope.None;
    public List<InterfaceExposure> PerInterface { get; set; } = [];
    public string Reason { get; set; } = "";

    public List<InterfaceExposure> Reachable => PerInterface.Where(i => i.Verdict == Verdict.Reachable).ToList();

    public List<string> Rules
    {
        get
        {
            var names = new List<string>();
            foreach (var ie in PerInterface)
            {
                foreach (var n in ie.AllowRules.Concat(ie.BlockRules).Concat(ie.UncertainRules))
                {
                    if (!names.Contains(n))
                    {
                        names.Add(n);
                    }
                }
            }
            return names;
        }
    }

    public JsonObject ToJson() => new()
    {
        ["listener"] = Listener.ToJson(),
        ["verdict"] = Verdict.Value(),
        ["scope"] = Scope.Value(),
        ["per_interface"] = new JsonArray(PerInterface.Select(i => (JsonNode)i.ToJson()).ToArray()),
        ["reason"] = Reason,
    };

    public static Exposure FromJson(JsonNode d) => new()
    {
        Listener = Listener.FromJson(Js.Get(d, "listener")!),
        Verdict = EnumText.ParseVerdict(Js.Str(Js.Get(d, "verdict"))),
        Scope = EnumText.ParseScope(Js.Str(Js.Get(d, "scope"))),
        PerInterface = (Js.Get(d, "per_interface") as JsonArray ?? []).Select(i => InterfaceExposure.FromJson(i!)).ToList(),
        Reason = Js.Str(Js.Get(d, "reason")),
    };
}

public sealed class FixOption
{
    public string FixId { get; set; } = "";
    public string Label { get; set; } = "";
    public JsonObject Params { get; set; } = [];
    public bool Disruptive { get; set; }
    public bool Recommended { get; set; }
    public bool GuidanceOnly { get; set; }
    /// <summary>An <c>Impact</c> as a dict.</summary>
    public JsonObject Impact { get; set; } = [];

    public JsonObject ToJson() => new()
    {
        ["fix_id"] = FixId,
        ["label"] = Label,
        ["params"] = Js.CloneObj(Params),
        ["disruptive"] = Disruptive,
        ["recommended"] = Recommended,
        ["guidance_only"] = GuidanceOnly,
        ["impact"] = Js.CloneObj(Impact),
    };

    public static FixOption FromJson(JsonNode d) => new()
    {
        FixId = Js.Str(Js.Get(d, "fix_id")),
        Label = Js.Str(Js.Get(d, "label")),
        Params = Js.CloneObj(Js.Get(d, "params") as JsonObject),
        Disruptive = Js.Bool(Js.Get(d, "disruptive")),
        Recommended = Js.Bool(Js.Get(d, "recommended")),
        GuidanceOnly = Js.Bool(Js.Get(d, "guidance_only")),
        Impact = Js.CloneObj(Js.Get(d, "impact") as JsonObject),
    };
}

public sealed class Finding
{
    /// <summary>Stable across scans, e.g. "rdp.nla_off" or "exposure.program:ollama.exe".</summary>
    public string Id { get; set; } = "";
    public string Check { get; set; } = "";
    public string Area { get; set; } = "";
    public string Title { get; set; } = "";
    public Severity Severity { get; set; }
    public string WhatItMeans { get; set; } = "";
    public List<(string Key, string Value)> Details { get; set; } = [];
    public List<FixOption> Fixes { get; set; } = [];
    public string LearnMore { get; set; } = "";
    public FindingStatus Status { get; set; } = FindingStatus.Open;
    public string? KeepKey { get; set; }
    public int Width { get; set; }
    public bool UserConfigured { get; set; }

    public bool Scored => Status == FindingStatus.Open && Severity > Severity.Info;

    public JsonObject ToJson() => new()
    {
        ["id"] = Id,
        ["check"] = Check,
        ["area"] = Area,
        ["title"] = Title,
        ["severity"] = Severity.Key(),
        ["what_it_means"] = WhatItMeans,
        ["details"] = new JsonArray(Details.Select(x => (JsonNode)new JsonArray(x.Key, x.Value)).ToArray()),
        ["fixes"] = new JsonArray(Fixes.Select(f => (JsonNode)f.ToJson()).ToArray()),
        ["learn_more"] = LearnMore,
        ["status"] = Status.Value(),
        ["keep_key"] = KeepKey,
        ["width"] = Width,
        ["user_configured"] = UserConfigured,
    };

    public static Finding FromJson(JsonNode d)
    {
        var sev = Js.Get(d, "severity");
        return new Finding
        {
            Id = Js.Str(Js.Get(d, "id")),
            Check = Js.Str(Js.Get(d, "check")),
            Area = Js.Str(Js.Get(d, "area")),
            Title = Js.Str(Js.Get(d, "title")),
            Severity = Js.IsString(sev) ? EnumText.ParseSeverity(Js.Str(sev)) : (Severity)Js.Int(sev),
            WhatItMeans = Js.Str(Js.Get(d, "what_it_means")),
            Details = (Js.Get(d, "details") as JsonArray ?? [])
                .Select(x => (Js.Str(x?[0]), Js.Str(x?[1]))).ToList(),
            Fixes = (Js.Get(d, "fixes") as JsonArray ?? []).Select(f => FixOption.FromJson(f!)).ToList(),
            LearnMore = Js.Str(Js.Get(d, "learn_more")),
            Status = EnumText.ParseStatus(Js.Str(Js.Get(d, "status"), "open")),
            KeepKey = Js.StrOrNull(Js.Get(d, "keep_key")),
            Width = Js.Int(Js.Get(d, "width")),
            UserConfigured = Js.Bool(Js.Get(d, "user_configured")),
        };
    }
}

/// <summary>One reversible primitive change, as shown in the preview and stored in the journal.</summary>
public sealed class ActionSpec
{
    public string Kind { get; set; } = "";
    public JsonObject Params { get; set; } = [];
    public string Summary { get; set; } = "";

    public ActionSpec()
    {
    }

    public ActionSpec(string kind, JsonObject parameters, string summary)
    {
        Kind = kind;
        Params = parameters;
        Summary = summary;
    }

    public JsonObject ToJson() => new()
    {
        ["kind"] = Kind,
        ["params"] = Js.CloneObj(Params),
        ["summary"] = Summary,
    };

    public static ActionSpec FromJson(JsonNode d) => new(
        Js.Str(Js.Get(d, "kind")),
        Js.CloneObj(Js.Get(d, "params") as JsonObject),
        Js.Str(Js.Get(d, "summary")));
}
