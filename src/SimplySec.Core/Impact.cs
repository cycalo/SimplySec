using System.Text.Json.Nodes;
using SimplySec.Core.Checks;
using SimplySec.Core.Compat;
using SimplySec.Core.Eval;
using SimplySec.Core.Model;
using static SimplySec.Core.Checks.CheckHelpers;

namespace SimplySec.Core;

public enum ImpactLevel
{
    InUse,
    MayAffect,
    NoneFound,
    Unknown,
}

/// <summary>What a fix would affect right now, with the evidence.</summary>
public sealed record Impact(ImpactLevel Level, string Headline, List<string> Evidence)
{
    public Impact(ImpactLevel level, string headline) : this(level, headline, []) { }

    public static string Value(ImpactLevel l) => l switch
    {
        ImpactLevel.InUse => "in_use",
        ImpactLevel.MayAffect => "may_affect",
        ImpactLevel.NoneFound => "none_found",
        ImpactLevel.Unknown => "unknown",
        _ => throw new ArgumentOutOfRangeException(nameof(l)),
    };

    public static int Rank(ImpactLevel l) => l switch
    {
        ImpactLevel.NoneFound => 0,
        ImpactLevel.Unknown => 1,
        ImpactLevel.MayAffect => 2,
        ImpactLevel.InUse => 3,
        _ => 0,
    };

    public static string Label(ImpactLevel l) => l switch
    {
        ImpactLevel.InUse => "In use right now",
        ImpactLevel.MayAffect => "Might affect something you use",
        ImpactLevel.NoneFound => "Nothing found using this",
        ImpactLevel.Unknown => "SimplySec can't check this",
        _ => "",
    };

    public static ImpactLevel Parse(string s) => s switch
    {
        "in_use" => ImpactLevel.InUse,
        "may_affect" => ImpactLevel.MayAffect,
        "none_found" => ImpactLevel.NoneFound,
        "unknown" => ImpactLevel.Unknown,
        _ => throw new ArgumentException(s),
    };

    public JsonObject ToJson() => new()
    {
        ["level"] = Value(Level),
        ["headline"] = Headline,
        ["evidence"] = Js.StrArray(Evidence),
    };

    public static Impact FromJson(JsonNode d) =>
        new(Parse(Js.Str(Js.Get(d, "level"))), Js.Str(Js.Get(d, "headline")), Js.StrList(Js.Get(d, "evidence")));
}

/// <summary>Evidence-based impact analysis for every fix (simulation and live usage).</summary>
public static class ImpactAnalysis
{
    public static Impact Worst(List<Impact> impacts)
    {
        if (impacts.Count == 0)
        {
            return new Impact(ImpactLevel.NoneFound, "Nothing found using this.");
        }
        var top = impacts[0];
        foreach (var i in impacts.Skip(1))
        {
            if (Impact.Rank(i.Level) > Impact.Rank(top.Level))
            {
                top = i;
            }
        }
        return new Impact(top.Level, top.Headline, impacts.SelectMany(i => i.Evidence).Distinct(StringComparer.Ordinal).ToList());
    }

    private static JsonNode Usage(ScanContext ctx) => ctx.Facts.GetOrEmpty("usage");

    private static bool IsShortName(string host)
    {
        host = host.Trim('[', ']');
        if (host.Length == 0 || host.Contains('.'))
        {
            return false;
        }
        return !PyIp.TryParseAddress(host, out _);
    }

    private static string UncHost(string? path)
    {
        var p = (path ?? "").TrimStart('\\');
        return p.Length > 0 ? p.Split('\\', 2)[0] : "";
    }

    /// <summary>Mapped drives and printers reached by a short name (may rely on NetBIOS/LLMNR).</summary>
    public static List<string> ShortNameDependencies(ScanContext ctx)
    {
        var u = Usage(ctx);
        var output = new List<string>();
        foreach (var m in Js.AsList(Js.Get(u, "mappings")))
        {
            var host = UncHost(S(GetOr(m, "remote", JsonValue.Create(""))));
            if (IsShortName(host))
            {
                var local = Js.Truthy(Js.Get(m, "local")) ? S(Js.Get(m, "local")) : "";
                output.Add($"Drive {local} → {S(Js.Get(m, "remote"))} uses the short name '{host}'");
            }
        }
        foreach (var p in Js.AsList(Js.Get(u, "printers")))
        {
            var host = UncHost(S(GetOr(p, "port", JsonValue.Create(""))));
            if (host.Length == 0)
            {
                host = S(GetOr(p, "computer", JsonValue.Create("")));
            }
            if (IsShortName(host))
            {
                output.Add($"Printer '{S(Js.Get(p, "name"))}' is reached by the short name '{host}'");
            }
        }
        return output;
    }

    public static List<JsonNode?> ConnectionsTo(ScanContext ctx, int port, int? pid = null) =>
        Js.AsList(Js.Get(Usage(ctx), "connections"))
            .Where(c => Js.NumEquals(Js.Get(c, "local_port"), port) && (pid is null || Js.NumEquals(Js.Get(c, "pid"), pid.Value)))
            .ToList();

    // ------------------------------------------------------------------ simulation

    public sealed record Change(Listener Listener, string Interface, Profile Profile, bool BecameReachable);

    private static (FirewallState, List<NetInterface>)? ApplyToModel(ScanContext ctx, List<ActionSpec> specs)
    {
        var fw = ctx.Firewall.Clone();
        var interfaces = ctx.Interfaces.Select(i => i.Clone()).ToList();
        var touched = false;
        foreach (var s in specs)
        {
            switch (s.Kind)
            {
                case "firewall.add_rule":
                    fw.Rules.Add(FirewallRule.FromJson(s.Params["rule"]!));
                    touched = true;
                    break;
                case "firewall.remove_rule":
                    var name = S(s.Params["name"]);
                    fw.Rules = fw.Rules.Where(r => r.Name != name).ToList();
                    touched = true;
                    break;
                case "firewall.profile":
                    var prof = (Profile)Js.Int(s.Params["profile"]);
                    if (!fw.Profiles.TryGetValue(prof, out var st))
                    {
                        throw new KeyNotFoundException(prof.ToString());
                    }
                    if (s.Params.ContainsKey("enabled"))
                    {
                        st.Enabled = Js.Truthy(s.Params["enabled"]);
                    }
                    if (s.Params.ContainsKey("default_inbound_block"))
                    {
                        st.DefaultInboundBlock = Js.Truthy(s.Params["default_inbound_block"]);
                    }
                    touched = true;
                    break;
                case "network.category":
                    foreach (var i in interfaces)
                    {
                        if (i.Index == Js.Int(s.Params["index"]))
                        {
                            i.Profile = PyStr.Upper(S(s.Params["profile"])) switch
                            {
                                "PRIVATE" => Profile.Private,
                                "PUBLIC" => Profile.Public,
                                "DOMAIN" => Profile.Domain,
                                var x => throw new KeyNotFoundException(x),
                            };
                            touched = true;
                        }
                    }
                    break;
            }
        }
        return touched ? (fw, interfaces) : null;
    }

    /// <summary>Only re-evaluate listeners a new block rule could match (fast path).</summary>
    private static List<Listener> Candidates(ScanContext ctx, List<ActionSpec> specs)
    {
        if (!specs.All(s => s.Kind == "firewall.add_rule"))
        {
            return ctx.Listeners;
        }
        var output = new List<Listener>();
        foreach (var s in specs)
        {
            var rule = FirewallRule.FromJson(s.Params["rule"]!);
            var app = Evaluator.NormalizeAppPath(rule.Application, ctx.Env);
            var ports = Evaluator.ParsePorts(rule.LocalPorts);
            foreach (var lst in ctx.Listeners)
            {
                if (app.Length > 0 && Evaluator.NormalizeAppPath(lst.Exe, ctx.Env) != app)
                {
                    continue;
                }
                if (!ports.Any && !ports.Ranges.Any(r => r.Lo <= lst.Port && lst.Port <= r.Hi))
                {
                    continue;
                }
                output.Add(lst);
            }
        }
        var seen = new HashSet<Listener>(ReferenceEqualityComparer.Instance);
        return output.Where(seen.Add).ToList();
    }

    public static List<Change>? Simulate(ScanContext ctx, List<ActionSpec> specs)
    {
        var model = ApplyToModel(ctx, specs);
        if (model is null)
        {
            return null;
        }
        var (fw, interfaces) = model.Value;
        var before = new Dictionary<string, Exposure>(StringComparer.Ordinal);
        foreach (var e in ctx.Exposures)
        {
            before[e.Listener.Key] = e;
        }
        var evalctx = new EvalContext(interfaces, ctx.Env);
        var rules = Evaluator.CompileRules(fw.Rules, evalctx.Env);
        var changes = new List<Change>();
        foreach (var lst in Candidates(ctx, specs))
        {
            before.TryGetValue(lst.Key, out var old);
            var nw = Evaluator.Evaluate(lst, fw, evalctx, rules);
            var oldV = new Dictionary<string, InterfaceExposure>(StringComparer.Ordinal);
            foreach (var ie in old?.PerInterface ?? [])
            {
                oldV[ie.Interface] = ie;
            }
            foreach (var ie in nw.PerInterface)
            {
                oldV.TryGetValue(ie.Interface, out var was);
                var wasReachable = was is not null && was.Verdict == Verdict.Reachable;
                var nowReachable = ie.Verdict == Verdict.Reachable;
                if (wasReachable != nowReachable)
                {
                    changes.Add(new Change(lst, ie.Interface, ie.Profile, nowReachable));
                }
            }
        }
        return changes;
    }

    private static string Describe(Listener lst)
    {
        var name = lst.Process.Length > 0 ? lst.Process : lst.Pid == 4 ? "Windows" : $"PID {lst.Pid}";
        return $"{name} ({PyStr.Upper(lst.Protocol)} {lst.Port})";
    }

    public static Impact FirewallImpact(ScanContext ctx, List<ActionSpec> specs, string program = "")
    {
        var changes = Simulate(ctx, specs);
        if (changes is null)
        {
            return new Impact(ImpactLevel.Unknown, "SimplySec could not simulate this change.");
        }
        var lost = new OrderedDictionary<string, List<string>>(StringComparer.Ordinal);
        var gained = new OrderedDictionary<string, List<string>>(StringComparer.Ordinal);
        var connected = new List<string>();
        var ifaceIps = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var i in ctx.Interfaces)
        {
            ifaceIps[i.Alias] = i.IpInterfaces().Select(x => x.Ip.ToString()).ToHashSet(StringComparer.Ordinal);
        }
        foreach (var ch in changes)
        {
            var target = ch.BecameReachable ? gained : lost;
            var where = $"{ch.Interface} ({ch.Profile.Label()})";
            var key = Describe(ch.Listener);
            if (!target.TryGetValue(key, out var list))
            {
                list = [];
                target[key] = list;
            }
            if (!list.Contains(where))
            {
                list.Add(where);
            }
            if (!ch.BecameReachable && ch.Listener.Protocol == "tcp")
            {
                foreach (var c in ConnectionsTo(ctx, ch.Listener.Port, ch.Listener.Pid))
                {
                    var localNode = GetOr(c, "local_ip", JsonValue.Create(""));
                    var local = S(localNode);
                    var ips = ifaceIps.TryGetValue(ch.Interface, out var set) ? set : [];
                    if ((Js.IsString(localNode) && ips.Contains(local)) || (ch.Listener.IsWildcard && !Js.Truthy(localNode)))
                    {
                        connected.Add($"{S(Js.Get(c, "remote_ip"))} is connected to {Describe(ch.Listener)} right now");
                    }
                }
            }
        }
        var evidence = lost.Select(kv => $"{kv.Key} would stop being reachable from {string.Join(", ", kv.Value)}").ToList();
        evidence.AddRange(gained.Select(kv => $"{kv.Key} would become reachable from {string.Join(", ", kv.Value)}"));
        if (connected.Count > 0)
        {
            return new Impact(ImpactLevel.InUse, "Another device is connected to this right now and would be cut off.",
                connected.Distinct(StringComparer.Ordinal).Concat(evidence).ToList());
        }
        if (lost.Count > 0 || gained.Count > 0)
        {
            var headline = lost.Count > 0 && gained.Count == 0
                ? "Nothing is connected right now, but if you use these from other devices they will stop working there:"
                : "This changes who can reach the following:";
            return new Impact(ImpactLevel.MayAffect, headline, evidence);
        }
        if (program.Length > 0)
        {
            var target = Evaluator.NormalizeAppPath(program, ctx.Env);
            var running = ctx.Listeners.Any(x => Evaluator.NormalizeAppPath(x.Exe, ctx.Env) == target);
            if (!running)
            {
                return new Impact(ImpactLevel.NoneFound,
                    "This program isn't accepting connections right now, so nothing would be cut off today.",
                    ["When it runs, devices on the affected networks won't be able to connect to it."]);
            }
        }
        return new Impact(ImpactLevel.NoneFound, "Nothing listening on this PC right now would be affected.");
    }

    // ------------------------------------------------------------------ per-fix rules

    private static long? DaysAgo(JsonNode? iso)
    {
        if (!Js.Truthy(iso))
        {
            return null;
        }
        var text = S(iso).Replace("Z", "+00:00", StringComparison.Ordinal);
        if (text.Length > 32)
        {
            text = text[..32];
        }
        var when = PyTime.FromIso(text);
        if (when is null)
        {
            return null;
        }
        return PyTime.Days(Ambient.UtcNow - when.Value);
    }

    private static Impact NameLookupImpact(ScanContext ctx, string what, int[] ports)
    {
        var deps = ShortNameDependencies(ctx);
        var conns = ports.SelectMany(p => ConnectionsTo(ctx, p)).ToList();
        if (conns.Count > 0)
        {
            return new Impact(ImpactLevel.InUse, $"Another device is using {what} with this PC right now.",
                conns.Select(c => $"{S(Js.Get(c, "remote_ip"))} is connected to port {S(Js.Get(c, "local_port"))}").Concat(deps).ToList());
        }
        if (deps.Count > 0)
        {
            return new Impact(ImpactLevel.MayAffect,
                "These connections use short names, which Windows may look up this way. Check they still work afterwards (undo is one click):", deps);
        }
        return new Impact(ImpactLevel.NoneFound, $"No mapped drives, printers or connections on this PC rely on {what}.",
            ["SimplySec can't see which names other devices look up, so very old devices are the only realistic risk."]);
    }

    public static readonly HashSet<string> NoUsageNeeded = new(StringComparer.Ordinal)
    {
        "accounts.uac_prompt",
        "system.autorun_off",
        "malware.update_signatures",
        "malware.cfa_on",
    };

    /// <summary>
    /// Impact of applying one fix, based on this scan. Never claims "nothing uses this" when the
    /// live-usage information could not be collected.
    /// </summary>
    public static Impact Assess(string fixId, JsonObject parameters, List<ActionSpec> specs, ScanContext? ctx)
    {
        var impact = AssessInner(fixId, parameters, specs, ctx);
        if (ctx is null || ctx.Facts.Status("usage") == "ok" || NoUsageNeeded.Contains(fixId))
        {
            return impact;
        }
        if (impact.Level == ImpactLevel.NoneFound)
        {
            return new Impact(ImpactLevel.Unknown,
                "SimplySec couldn't check what is in use right now, so it can't say whether anything relies on this.", impact.Evidence);
        }
        if (impact.Level == ImpactLevel.MayAffect && impact.Headline.StartsWith("Nothing is connected", StringComparison.Ordinal))
        {
            return new Impact(ImpactLevel.MayAffect,
                "SimplySec couldn't check current connections. If you use these from other devices they will stop working there:", impact.Evidence);
        }
        return impact;
    }

    private static Impact AssessInner(string fixId, JsonObject parameters, List<ActionSpec> specs, ScanContext? ctx)
    {
        if (ctx is null)
        {
            return new Impact(ImpactLevel.Unknown, "Scan first to see what this would affect.");
        }
        var u = Usage(ctx);
        if (fixId.StartsWith("exposure.", StringComparison.Ordinal) ||
            fixId is "firewall.enable" or "firewall.default_block" or "network.mark_private" or "housekeeping.remove_v1_rules")
        {
            return FirewallImpact(ctx, specs, S(GetOr(parameters, "exe", JsonValue.Create(""))));
        }
        switch (fixId)
        {
            case "legacy.netbios_off":
                return NameLookupImpact(ctx, "NetBIOS (old Windows file sharing)", [139]);
            case "legacy.llmnr_off":
                return NameLookupImpact(ctx, "LLMNR name lookups", []);
            case "legacy.smb1_off":
            {
                if (!Js.PyEquals(Js.Get(u, "smb_sessions_status"), JsonValue.Create("ok")))
                {
                    return new Impact(ImpactLevel.Unknown,
                        "Only administrators can see which devices use SMBv1. Modern Windows, Mac, Android and NAS devices don't.");
                }
                var old = Js.AsList(Js.Get(u, "smb_sessions"))
                    .Where(s => S(GetOr(s, "dialect", JsonValue.Create(""))).StartsWith('1')).ToList();
                if (old.Count > 0)
                {
                    return new Impact(ImpactLevel.InUse, "A device is using SMBv1 to reach this PC right now.",
                        old.Select(s => $"{S(Js.Get(s, "client"))} ({S(Js.Get(s, "user"))})").ToList());
                }
                return new Impact(ImpactLevel.NoneFound, "No device is using SMBv1 with this PC.");
            }
            case "rdp.disable":
            case "rdp.require_nla":
            {
                var evidence = new List<string>();
                if (Js.Truthy(Js.Get(u, "remote_session")))
                {
                    evidence.Add("You are using this PC through Remote Desktop right now.");
                }
                evidence.AddRange(Js.AsList(Js.Get(u, "rdp_sessions")).Select(s => $"Remote Desktop session '{S(Js.Get(s, "station"))}' is active"));
                evidence.AddRange(ConnectionsTo(ctx, 3389).Select(c => $"{S(Js.Get(c, "remote_ip"))} is connected to Remote Desktop"));
                if (evidence.Count > 0 && fixId == "rdp.disable")
                {
                    return new Impact(ImpactLevel.InUse, "Remote Desktop is in use: turning it off would disconnect it.",
                        evidence.Distinct(StringComparer.Ordinal).ToList());
                }
                if (evidence.Count > 0)
                {
                    return new Impact(ImpactLevel.MayAffect, "Remote Desktop is in use; very old clients would no longer connect.",
                        evidence.Distinct(StringComparer.Ordinal).ToList());
                }
                return new Impact(ImpactLevel.NoneFound, "Nobody is connected through Remote Desktop right now.");
            }
            case "rdp.remote_assistance_off":
                if (Js.Truthy(Js.Get(u, "msra_running")))
                {
                    return new Impact(ImpactLevel.InUse, "Windows Remote Assistance is open right now.", ["msra.exe is running"]);
                }
                return new Impact(ImpactLevel.NoneFound, "Remote Assistance isn't running. Quick Assist keeps working.");
            case "accounts.guest_off":
            {
                var lastNode = Js.AsList(Js.Get(u, "last_logons"))
                    .Where(x => S(GetOr(x, "sid", JsonValue.Create(""))).EndsWith("-501", StringComparison.Ordinal))
                    .Select(x => Js.Get(x, "last")).FirstOrDefault();
                var days = DaysAgo(lastNode);
                if (days is null)
                {
                    return new Impact(ImpactLevel.NoneFound, "The Guest account has never been used to sign in.");
                }
                if (days <= 30)
                {
                    return new Impact(ImpactLevel.InUse, $"Someone signed in as Guest {days} day(s) ago.", ["Make sure they have their own account first."]);
                }
                return new Impact(ImpactLevel.MayAffect, $"The Guest account was last used {days} days ago.");
            }
            case "accounts.blank_password_limit":
            {
                var accounts = ctx.Facts.GetOrEmpty("accounts");
                var blank = Js.AsList(Js.Get(accounts, "users"))
                    .Where(a => Js.Truthy(Js.Get(a, "enabled")) && Js.IsBool(Js.Get(a, "password_required")) && !Js.Get(a, "password_required")!.GetValue<bool>())
                    .Select(a => S(Js.Get(a, "name"))).ToList();
                if (blank.Count > 0)
                {
                    return new Impact(ImpactLevel.MayAffect,
                        "These accounts have no password; other PCs could no longer open this PC's shares with them:", blank);
                }
                return new Impact(ImpactLevel.NoneFound, "No enabled account here is set up without a password.");
            }
            case "malware.cfa_on":
                return new Impact(ImpactLevel.MayAffect,
                    "Some programs (older games, editors, backup tools) may be stopped from saving into Documents, Pictures or Desktop until you allow them in Windows Security.");
            case "wifi.manual_connect":
            {
                var connected = ctx.ActiveInterfaces().Select(i => i.NetworkName).ToHashSet(StringComparer.Ordinal);
                var names = (Js.Get(parameters, "profiles") as JsonArray ?? [])
                    .Where(n => Js.IsString(n) && connected.Contains(n!.GetValue<string>()))
                    .Select(n => S(n)).ToList();
                if (names.Count > 0)
                {
                    return new Impact(ImpactLevel.MayAffect,
                        "You're connected to this network now; you'll stay connected but must pick it by hand next time.", names);
                }
                return new Impact(ImpactLevel.NoneFound, "You're not connected to these networks now; the saved networks stay.");
            }
            case "accounts.uac_prompt":
            case "system.autorun_off":
            case "malware.update_signatures":
                return new Impact(ImpactLevel.NoneFound, "Nothing stops working; Windows just behaves as it does by default.");
        }
        return new Impact(ImpactLevel.Unknown, "SimplySec has no specific check for what this affects.");
    }
}
