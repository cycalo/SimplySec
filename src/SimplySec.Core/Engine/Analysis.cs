using System.Text.Json.Nodes;
using SimplySec.Core.Checks;
using SimplySec.Core.Compat;
using SimplySec.Core.Eval;
using SimplySec.Core.Knowledge;
using SimplySec.Core.Model;

namespace SimplySec.Core.Engine;

/// <summary>Everything collected from the PC for one scan (pure data, replayable from JSON).</summary>
public sealed class RawScan
{
    public JsonObject Facts { get; set; } = [];
    public List<Listener> Listeners { get; set; } = [];
    public FirewallState Firewall { get; set; } = new();
    public List<NetInterface> Interfaces { get; set; } = [];
    public OrderedDictionary<string, SignatureInfo> Signatures { get; set; } = new(StringComparer.Ordinal);
    public OrderedDictionary<string, string> Env { get; set; } = new(StringComparer.Ordinal);
    public bool IsAdmin { get; set; }
    public string WindowsDir { get; set; } = @"C:\Windows";
    public List<string> Errors { get; set; } = [];
    public string Started { get; set; } = "";
    public double Duration { get; set; }

    public JsonObject ToJson()
    {
        var sigs = new JsonObject();
        foreach (var (k, v) in Signatures)
        {
            sigs[k] = new JsonObject { ["status"] = v.Status, ["publisher"] = v.Publisher };
        }
        var env = new JsonObject();
        foreach (var (k, v) in Env)
        {
            env[k] = v;
        }
        return new JsonObject
        {
            ["facts"] = Js.CloneObj(Facts),
            ["listeners"] = new JsonArray(Listeners.Select(x => (JsonNode)x.ToJson()).ToArray()),
            ["firewall"] = Firewall.ToJson(),
            ["interfaces"] = new JsonArray(Interfaces.Select(i => (JsonNode)i.ToJson()).ToArray()),
            ["signatures"] = sigs,
            ["env"] = env,
            ["is_admin"] = IsAdmin,
            ["windows_dir"] = WindowsDir,
            ["errors"] = Js.StrArray(Errors),
            ["started"] = Started,
            ["duration"] = Duration,
        };
    }

    public static RawScan FromJson(JsonNode d)
    {
        var raw = new RawScan
        {
            Facts = Js.CloneObj(Js.Get(d, "facts") as JsonObject),
            Listeners = (Js.Get(d, "listeners") as JsonArray ?? []).Select(x => Listener.FromJson(x!)).ToList(),
            Firewall = FirewallState.FromJson(Js.Get(d, "firewall")!),
            Interfaces = (Js.Get(d, "interfaces") as JsonArray ?? []).Select(i => NetInterface.FromJson(i!)).ToList(),
            IsAdmin = Js.Bool(Js.Get(d, "is_admin")),
            WindowsDir = Js.Has(d, "windows_dir") ? Js.Str(Js.Get(d, "windows_dir")) : @"C:\Windows",
            Errors = Js.StrList(Js.Get(d, "errors")),
            Started = Js.Str(Js.Get(d, "started")),
            Duration = Js.Double(Js.Get(d, "duration")) ?? 0,
        };
        foreach (var (k, v) in Js.Get(d, "signatures") as JsonObject ?? [])
        {
            raw.Signatures[k] = new SignatureInfo(Js.Str(Js.Get(v, "status")), Js.Has(v, "publisher") ? Js.Str(Js.Get(v, "publisher")) : "");
        }
        foreach (var (k, v) in Js.Get(d, "env") as JsonObject ?? [])
        {
            raw.Env[k] = Js.Str(v);
        }
        return raw;
    }
}

public sealed class PortRow
{
    public string Protocol { get; set; } = "";
    public int Port { get; set; }
    public int Pid { get; set; }
    public string Process { get; set; } = "";
    public string Exe { get; set; } = "";
    public string Publisher { get; set; } = "";
    public List<string> Services { get; set; } = [];
    public string ListeningOn { get; set; } = "";
    public string ReachableFrom { get; set; } = "";
    public Verdict Verdict { get; set; }
    public Scope Scope { get; set; }
    public Severity Risk { get; set; }
    public string Reason { get; set; } = "";
    public List<string> Rules { get; set; } = [];
    public string? FindingId { get; set; }
    public List<string> Connected { get; set; } = [];

    public JsonObject ToJson() => new()
    {
        ["protocol"] = Protocol,
        ["port"] = Port,
        ["pid"] = Pid,
        ["process"] = Process,
        ["exe"] = Exe,
        ["publisher"] = Publisher,
        ["services"] = Js.StrArray(Services),
        ["listening_on"] = ListeningOn,
        ["reachable_from"] = ReachableFrom,
        ["verdict"] = Verdict.Value(),
        ["scope"] = Scope.Value(),
        ["risk"] = Risk.Key(),
        ["reason"] = Reason,
        ["rules"] = Js.StrArray(Rules),
        ["finding_id"] = FindingId,
        ["connected"] = Js.StrArray(Connected),
    };

    public static PortRow FromJson(JsonNode d) => new()
    {
        Protocol = Js.Str(Js.Get(d, "protocol")),
        Port = Js.Int(Js.Get(d, "port")),
        Pid = Js.Int(Js.Get(d, "pid")),
        Process = Js.Str(Js.Get(d, "process")),
        Exe = Js.Str(Js.Get(d, "exe")),
        Publisher = Js.Str(Js.Get(d, "publisher")),
        Services = Js.StrList(Js.Get(d, "services")),
        ListeningOn = Js.Str(Js.Get(d, "listening_on")),
        ReachableFrom = Js.Str(Js.Get(d, "reachable_from")),
        Verdict = EnumText.ParseVerdict(Js.Str(Js.Get(d, "verdict"))),
        Scope = EnumText.ParseScope(Js.Str(Js.Get(d, "scope"))),
        Risk = EnumText.ParseSeverity(Js.Str(Js.Get(d, "risk"))),
        Reason = Js.Str(Js.Get(d, "reason")),
        Rules = Js.StrList(Js.Get(d, "rules")),
        FindingId = Js.StrOrNull(Js.Get(d, "finding_id")),
        Connected = Js.StrList(Js.Get(d, "connected")),
    };
}

public sealed class ScanResult
{
    public string Started { get; set; } = "";
    public double Duration { get; set; }
    public string Computer { get; set; } = "";
    public bool IsAdmin { get; set; }
    public string Version { get; set; } = AppInfo.Version;
    public List<NetInterface> Interfaces { get; set; } = [];
    public List<FirewallProfileState> FirewallProfiles { get; set; } = [];
    public bool FirewallManaged { get; set; }
    public List<Exposure> Exposures { get; set; } = [];
    public List<PortRow> Ports { get; set; } = [];
    public List<Finding> Findings { get; set; } = [];
    public int Score { get; set; }
    public string Grade { get; set; } = "?";
    public List<string> Errors { get; set; } = [];
    public JsonObject Facts { get; set; } = [];
    /// <summary>M2: devices, router, networks.</summary>
    public JsonObject Extras { get; set; } = [];

    public List<Finding> OpenFindings =>
        Findings.Where(f => f.Status == FindingStatus.Open && f.Severity > Severity.Info).ToList();

    public JsonObject Counts()
    {
        var output = new JsonObject { ["critical"] = 0, ["high"] = 0, ["medium"] = 0, ["low"] = 0 };
        foreach (var f in OpenFindings)
        {
            output[f.Severity.Key()] = Js.Int(output[f.Severity.Key()]) + 1;
        }
        return output;
    }

    public Finding? Finding(string id) => Findings.FirstOrDefault(f => f.Id == id);

    public List<string> NetworkStatus()
    {
        var profiles = new Dictionary<Profile, FirewallProfileState>();
        foreach (var p in FirewallProfiles)
        {
            profiles[p.Profile] = p;
        }
        var lines = new List<string>();
        foreach (var iface in Interfaces)
        {
            if (!iface.Up || iface.Kind == InterfaceKind.Loopback || iface.IpInterfaces().Count == 0)
            {
                continue;
            }
            if (iface.Kind == InterfaceKind.Virtual)
            {
                continue;
            }
            var prof = iface.EffectiveProfile;
            profiles.TryGetValue(prof, out var st);
            var fw = st is not null && st.Enabled ? "firewall on" : "FIREWALL OFF";
            var assumed = iface.Profile is null ? " (assumed)" : "";
            lines.Add($"{iface.Alias}: {prof.Label()}{assumed} network, {fw}");
        }
        return lines;
    }

    public JsonObject ToJson(bool includeFacts = true)
    {
        var d = new JsonObject
        {
            ["version"] = Version,
            ["started"] = Started,
            ["duration"] = Math.Round(Duration, 2, MidpointRounding.ToEven),
            ["computer"] = Computer,
            ["is_admin"] = IsAdmin,
            ["score"] = Score,
            ["grade"] = Grade,
            ["counts"] = Counts(),
            ["network"] = Js.StrArray(NetworkStatus()),
            ["interfaces"] = new JsonArray(Interfaces.Select(i => (JsonNode)i.ToJson()).ToArray()),
            ["firewall"] = new JsonObject
            {
                ["managed_by_policy"] = FirewallManaged,
                ["profiles"] = new JsonArray(FirewallProfiles.Select(p => (JsonNode)p.ToJson()).ToArray()),
            },
            ["findings"] = new JsonArray(Findings.Select(f => (JsonNode)f.ToJson()).ToArray()),
            ["ports"] = new JsonArray(Ports.Select(p => (JsonNode)p.ToJson()).ToArray()),
            ["exposures"] = new JsonArray(Exposures.Select(e => (JsonNode)e.ToJson()).ToArray()),
            ["errors"] = Js.StrArray(Errors),
            ["extras"] = Js.CloneObj(Extras),
        };
        if (includeFacts)
        {
            d["facts"] = Js.CloneObj(Facts);
        }
        return d;
    }

    public static ScanResult FromJson(JsonNode d)
    {
        var fw = Js.Get(d, "firewall");
        return new ScanResult
        {
            Started = Js.Str(Js.Get(d, "started")),
            Duration = Js.Double(Js.Get(d, "duration")) ?? 0,
            Computer = Js.Str(Js.Get(d, "computer")),
            IsAdmin = Js.Bool(Js.Get(d, "is_admin")),
            Version = Js.Str(Js.Get(d, "version")),
            Interfaces = (Js.Get(d, "interfaces") as JsonArray ?? []).Select(i => NetInterface.FromJson(i!)).ToList(),
            FirewallProfiles = (Js.Get(fw, "profiles") as JsonArray ?? []).Select(p => FirewallProfileState.FromJson(p!)).ToList(),
            FirewallManaged = Js.Bool(Js.Get(fw, "managed_by_policy")),
            Exposures = (Js.Get(d, "exposures") as JsonArray ?? []).Select(e => Exposure.FromJson(e!)).ToList(),
            Ports = (Js.Get(d, "ports") as JsonArray ?? []).Select(p => PortRow.FromJson(p!)).ToList(),
            Findings = (Js.Get(d, "findings") as JsonArray ?? []).Select(f => Model.Finding.FromJson(f!)).ToList(),
            Score = Js.Int(Js.Get(d, "score")),
            Grade = Js.Has(d, "grade") ? Js.Str(Js.Get(d, "grade")) : "?",
            Errors = Js.StrList(Js.Get(d, "errors")),
            Facts = Js.CloneObj(Js.Get(d, "facts") as JsonObject),
            Extras = Js.CloneObj(Js.Get(d, "extras") as JsonObject),
        };
    }
}

public static class AppInfo
{
    public const string Version = "3.0.0";
}

// --------------------------------------------------------------------------- plans

public sealed record Selection(string FixId, JsonObject Params, string? FindingId = null)
{
    public Selection(string fixId) : this(fixId, []) { }
}

public sealed class PlannedFix
{
    public required FixDef Fix { get; init; }
    public required JsonObject Params { get; init; }
    public string? FindingId { get; init; }
    public required List<ActionSpec> Specs { get; init; }
    public required List<FixWarning> Warnings { get; init; }
    public Impact? Impact { get; init; }
}

public sealed class Plan
{
    public List<PlannedFix> Items { get; } = [];
    public List<string> Refused { get; } = [];

    public List<ActionSpec> Specs => Items.SelectMany(i => i.Specs).ToList();

    public List<string> MightBreak =>
        Items.Where(i => i.Fix.MightBreak.Length > 0).Select(i => $"{i.Fix.Label}: {i.Fix.MightBreak}").ToList();

    public bool TouchesFirewall => Specs.Any(s => s.Kind.StartsWith("firewall.", StringComparison.Ordinal));
}

/// <summary>The pure half of the engine: facts in, findings, port table and score out.</summary>
public static class Analysis
{
    private static readonly Verdict[] VerdictOrder = [Verdict.Reachable, Verdict.Uncertain, Verdict.Blocked, Verdict.LocalOnly];

    public static List<PortGroup> GroupExposures(List<Exposure> exposures)
    {
        var groups = new OrderedDictionary<(string, int, int), PortGroup>();
        foreach (var e in exposures)
        {
            var lst = e.Listener;
            var key = (lst.Protocol, lst.Port, lst.Pid);
            if (!groups.TryGetValue(key, out var g))
            {
                g = new PortGroup { Protocol = lst.Protocol, Port = lst.Port, Pid = lst.Pid, Process = lst.Process, Exe = lst.Exe, Services = lst.Services };
                groups[key] = g;
            }
            g.Exposures.Add(e);
        }
        return groups.Values.OrderBy(g => g.Protocol, StringComparer.Ordinal).ThenBy(g => g.Port).ThenBy(g => g.Pid).ToList();
    }

    private static string ListeningOn(PortGroup g, List<NetInterface> interfaces)
    {
        var addrs = g.Addresses;
        if (g.Exposures.All(e => e.Listener.IsLoopback))
        {
            return "This PC only (" + string.Join(", ", addrs.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)) + ")";
        }
        if (g.Exposures.Any(e => e.Listener.IsWildcard))
        {
            return "All networks";
        }
        var parts = new List<string>();
        foreach (var a in addrs.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))
        {
            var iface = interfaces.FirstOrDefault(i => i.HasIp(a));
            parts.Add(iface is not null ? $"{iface.Alias} ({a})" : a);
        }
        return string.Join(", ", parts);
    }

    private static (Verdict, Scope, string, string, List<string>) ReachableFrom(PortGroup g)
    {
        var verdicts = g.Exposures.Select(e => e.Verdict).ToHashSet();
        var verdict = VerdictOrder.First(verdicts.Contains);
        var rules = new List<string>();
        foreach (var e in g.Exposures)
        {
            foreach (var r in e.Rules)
            {
                if (!rules.Contains(r))
                {
                    rules.Add(r);
                }
            }
        }
        if (verdict == Verdict.LocalOnly)
        {
            return (verdict, Scope.None, "Only this PC", g.Exposures[0].Reason, rules);
        }
        if (verdict == Verdict.Blocked)
        {
            return (verdict, Scope.None, "Nobody (blocked by the firewall)", g.Exposures.First(e => e.Verdict == Verdict.Blocked).Reason, rules);
        }
        if (verdict == Verdict.Uncertain)
        {
            return (verdict, Scope.None, "Uncertain", g.Exposures.First(e => e.Verdict == Verdict.Uncertain).Reason, rules);
        }
        var parts = new List<string>();
        var scope = Scope.None;
        var reasons = new List<string>();
        foreach (var e in g.Exposures)
        {
            foreach (var ie in e.Reachable)
            {
                scope = EnumText.MaxRank(scope, ie.Scope);
                string text;
                if (ie.InterfaceKind == InterfaceKind.Vpn)
                {
                    text = $"{ie.Interface} network";
                }
                else if (ie.InterfaceKind == InterfaceKind.Virtual)
                {
                    text = $"VMs ({ie.Interface})";
                }
                else if (ie.Scope == Scope.Anyone)
                {
                    text = $"Anyone on {ie.Interface} ({ie.Profile.Label()})";
                }
                else if (ie.Scope == Scope.LocalSubnet)
                {
                    text = $"Local subnet on {ie.Interface} ({ie.Profile.Label()})";
                }
                else
                {
                    text = $"Some addresses on {ie.Interface}";
                }
                if (!parts.Contains(text))
                {
                    parts.Add(text);
                    reasons.Add(ie.Reason);
                }
            }
        }
        return (verdict, scope, string.Join("; ", parts), string.Join(" ", reasons), rules);
    }

    /// <summary>Work out, for every fix offered on an open finding, what it would affect right now.</summary>
    public static void AttachImpacts(List<Finding> findings, ScanContext ctx)
    {
        foreach (var f in findings)
        {
            if (f.Status != FindingStatus.Open)
            {
                continue;
            }
            foreach (var opt in f.Fixes)
            {
                if (!Registry.Fixes.TryGetValue(opt.FixId, out var fix) || fix.Build is null)
                {
                    continue;
                }
                Impact impact;
                try
                {
                    impact = ImpactAnalysis.Assess(fix.Id, opt.Params, fix.Build(opt.Params), ctx);
                }
                catch (Exception)
                {
                    impact = new Impact(ImpactLevel.Unknown, "SimplySec could not work out what this affects.");
                }
                opt.Impact = impact.ToJson();
            }
        }
    }

    public static ScanResult Analyze(RawScan raw, KnowledgeBase? kb = null, Dictionary<string, int>? accepted = null, Func<string, bool>? fileExists = null) =>
        AnalyzeWithContext(raw, kb, accepted, fileExists).Result;

    public static (ScanResult Result, ScanContext Context) AnalyzeWithContext(
        RawScan raw, KnowledgeBase? kb = null, Dictionary<string, int>? accepted = null, Func<string, bool>? fileExists = null)
    {
        kb ??= KnowledgeBase.Get();
        var env = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (k, v) in raw.Env)
        {
            env[PyStr.Upper(k)] = v;
        }
        var evalctx = new EvalContext(raw.Interfaces, env);
        var exposures = Evaluator.EvaluateAll(raw.Listeners, raw.Firewall, evalctx);
        var groups = GroupExposures(exposures);
        var signatures = new Dictionary<string, SignatureInfo>(StringComparer.Ordinal);
        foreach (var (k, v) in raw.Signatures)
        {
            signatures[k] = v;
        }
        var ctx = new ScanContext
        {
            Facts = new Facts(raw.Facts),
            Listeners = raw.Listeners,
            Exposures = exposures,
            Groups = groups,
            Interfaces = raw.Interfaces,
            Firewall = raw.Firewall,
            Kb = kb,
            Signatures = signatures,
            IsAdmin = raw.IsAdmin,
            Env = env,
            Accepted = accepted ?? new Dictionary<string, int>(StringComparer.Ordinal),
            WindowsDir = raw.WindowsDir,
            FileExists = fileExists ?? (_ => true),
        };
        var findings = new List<Finding>();
        var errors = new List<string>(raw.Errors);
        foreach (var check in Registry.Checks)
        {
            try
            {
                findings.AddRange(check.Run(ctx));
            }
            catch (Exception exc)
            {
                errors.Add($"check {check.Id} failed: {exc.Message}");
                findings.Add(new Finding
                {
                    Id = $"{check.Id}.error",
                    Check = check.Id,
                    Area = check.Area,
                    Title = $"The {check.Area} check could not run",
                    Severity = Severity.Info,
                    WhatItMeans = $"Error: {exc.Message}. This area is reported as unknown, not as safe.",
                });
            }
        }
        findings = findings
            .OrderBy(f => f.Status != FindingStatus.Open)
            .ThenBy(f => -(int)f.Severity)
            .ThenBy(f => f.Area, StringComparer.Ordinal)
            .ThenBy(f => f.Title, StringComparer.Ordinal)
            .ToList();
        AttachImpacts(findings, ctx);

        var bySubject = new HashSet<string>(StringComparer.Ordinal);
        foreach (var f in findings.Where(f => f.Check == "exposure"))
        {
            bySubject.Add(f.Id);
        }
        var usage = ctx.Facts.GetOrEmpty("usage");
        var rows = new List<PortRow>();
        foreach (var g in groups)
        {
            var (verdict, scope, reach, reason, rules) = ReachableFrom(g);
            var risk = Severity.Info;
            string? findingId = null;
            if (verdict == Verdict.Reachable)
            {
                (risk, findingId) = ExposureCheck.ExposureSeverityForGroup(g, ctx);
                if (!bySubject.Contains(findingId))
                {
                    findingId = null;
                }
            }
            var sig = ctx.Signature(g.Exe);
            var connected = Js.AsList(Js.Get(usage, "connections"))
                .Where(c => Js.NumEquals(Js.Get(c, "local_port"), g.Port) && Js.NumEquals(Js.Get(c, "pid"), g.Pid) && g.Protocol == "tcp")
                .Select(c => Js.PyRepr(Js.Get(c, "remote_ip")))
                .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();
            rows.Add(new PortRow
            {
                Protocol = g.Protocol,
                Port = g.Port,
                Pid = g.Pid,
                Process = g.Process.Length > 0 ? g.Process : g.Pid == 4 ? "System" : $"PID {g.Pid}",
                Exe = g.Exe,
                Publisher = sig is not null ? sig.Publisher : g.Pid == 4 ? "Microsoft (Windows kernel)" : "",
                Services = [.. g.Services ?? []],
                ListeningOn = ListeningOn(g, raw.Interfaces),
                ReachableFrom = reach,
                Verdict = verdict,
                Scope = scope,
                Risk = risk,
                Reason = reason,
                Rules = rules,
                FindingId = findingId,
                Connected = connected,
            });
        }
        var value = Scoring.Score(findings);
        var system = ctx.Facts.GetOrEmpty("system");
        var computer = Js.Truthy(Js.Get(system, "computer")) ? Js.PyRepr(Js.Get(system, "computer")) : Environment.GetEnvironmentVariable("COMPUTERNAME") ?? "";
        var result = new ScanResult
        {
            Started = raw.Started.Length > 0 ? raw.Started : PyTime.NowIsoSeconds(),
            Duration = raw.Duration,
            Computer = computer,
            IsAdmin = raw.IsAdmin,
            Interfaces = raw.Interfaces,
            FirewallProfiles = [.. raw.Firewall.Profiles.Values],
            FirewallManaged = raw.Firewall.ManagedByPolicy,
            Exposures = exposures,
            Ports = rows,
            Findings = findings,
            Score = value,
            Grade = Scoring.Grade(value, findings),
            Errors = errors,
            Facts = raw.Facts,
        };
        return (result, ctx);
    }

    public static Plan BuildPlan(List<Selection> selections, ScanContext? ctx = null)
    {
        var plan = new Plan();
        foreach (var sel in selections)
        {
            if (!Registry.Fixes.TryGetValue(sel.FixId, out var fix))
            {
                plan.Refused.Add($"unknown fix {sel.FixId}");
                continue;
            }
            if (fix.Build is null)
            {
                plan.Refused.Add($"{fix.Label} only opens Windows settings");
                continue;
            }
            var specs = fix.Build(sel.Params);
            var bad = specs.Where(s => !Registry.SpecAllowed(s)).ToList();
            if (bad.Count > 0)
            {
                plan.Refused.Add($"{fix.Label}: refused, not on the allow-list ({bad[0].Kind})");
                continue;
            }
            var warnings = fix.Warnings is not null && ctx is not null ? fix.Warnings(ctx, sel.Params) : [];
            var impact = ctx is not null ? ImpactAnalysis.Assess(fix.Id, sel.Params, specs, ctx) : null;
            plan.Items.Add(new PlannedFix { Fix = fix, Params = sel.Params, FindingId = sel.FindingId, Specs = specs, Warnings = warnings, Impact = impact });
        }
        return plan;
    }

    /// <summary>
    /// 'Fix recommended': only non-disruptive fixes on open findings, never one that something
    /// is using right now. Returns (selections, skipped as (finding title, why)).
    /// </summary>
    public static (List<Selection>, List<(string, string)>) RecommendedSplit(ScanResult? result)
    {
        if (result is null)
        {
            return ([], []);
        }
        var output = new List<Selection>();
        var skipped = new List<(string, string)>();
        foreach (var f in result.OpenFindings)
        {
            foreach (var opt in f.Fixes)
            {
                if (opt.Recommended && !opt.Disruptive && !opt.GuidanceOnly)
                {
                    if (Js.PyEquals(Js.Get(opt.Impact, "level"), JsonValue.Create("in_use")))
                    {
                        skipped.Add((f.Title, Js.Has(opt.Impact, "headline") ? Js.PyRepr(opt.Impact["headline"]) : ""));
                    }
                    else
                    {
                        output.Add(new Selection(opt.FixId, opt.Params, f.Id));
                    }
                    break;
                }
            }
        }
        return (output, skipped);
    }
}
