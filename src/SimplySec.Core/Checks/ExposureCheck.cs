using System.Text.Json.Nodes;
using SimplySec.Core.Compat;
using SimplySec.Core.Eval;
using SimplySec.Core.Knowledge;
using SimplySec.Core.Model;
using static SimplySec.Core.Checks.CheckHelpers;

namespace SimplySec.Core.Checks;

/// <summary>
/// Exposure findings: what other devices can actually reach, by program or port. Findings about
/// known apps are about who can reach them, never about the app being bad.
/// </summary>
public static class ExposureCheck
{
    public const string CheckId = "exposure";
    public const string Area = "Exposure";
    public const string Group = "SimplySec";

    public sealed record Identity(
        string Label, string Explain, Severity Base, ProgramInfo? Program, IPortOrRange? Port,
        bool ThirdParty, string SubjectKind, string Subject);

    public static bool IsUserWritable(string? path, IReadOnlyDictionary<string, string> env)
    {
        var p = PyStr.Lower(path);
        if (p.Length == 0)
        {
            return false;
        }
        var roots = new List<string> { @"c:\users\" };
        foreach (var v in new[] { "USERPROFILE", "LOCALAPPDATA", "APPDATA", "TEMP", "TMP", "PROGRAMDATA" })
        {
            if (env.TryGetValue(v, out var value) && value.Length > 0)
            {
                roots.Add(PyStr.Lower(value).TrimEnd('\\') + "\\");
            }
        }
        return roots.Any(r => p.StartsWith(r, StringComparison.Ordinal));
    }

    /// <summary>True when the user set an env var that binds the program to the network on purpose.</summary>
    public static bool UserConfigured(ProgramInfo? program, IReadOnlyDictionary<string, string> env)
    {
        if (program is null || program.IntentEnv.Length == 0)
        {
            return false;
        }
        var value = PyStr.Strip(env.TryGetValue(PyStr.Upper(program.IntentEnv), out var v) ? v : "");
        if (value.Length == 0)
        {
            return false;
        }
        var parts = value.Split("://");
        var host = parts[^1];
        if (host.StartsWith('['))
        {
            host = host[1..].Split(']')[0];
        }
        else if (host.Count(c => c == ':') == 1)
        {
            host = host.Split(':')[0];
        }
        if (host is "" or "*" or "0.0.0.0" or "::")
        {
            return true;
        }
        if (PyStr.Lower(host) == "localhost")
        {
            return false;
        }
        return PyIp.TryParseAddress(host, out var ip) ? !ip.IsLoopback : true;
    }

    private static string Capitalize(string s) => s.Length == 0 ? s : PyStr.Upper(s[..1]) + s[1..];

    public static Identity Identify(PortGroup g, ScanContext ctx)
    {
        var kb = ctx.Kb;
        var program = g.Pid != 4 ? kb.Program(g.Exe.Length > 0 ? g.Exe : g.Process) : null;
        var services = (g.Services ?? []).Select(kb.Service).Where(s => s is not null).Select(s => s!).ToList();
        var exact = kb.Port(g.Protocol, g.Port);
        var portOrRange = (IPortOrRange?)exact ?? kb.PortOrRange(g.Protocol, g.Port);
        var thirdParty = g.Pid != 4 && g.Exe.Length > 0 && !ctx.IsWindowsBinary(g.Exe);

        var risks = new List<Severity>();
        if (exact is not null)
        {
            risks.Add(exact.Risk);
        }
        if (exact is null || !exact.Discovery)
        {
            if (program is not null)
            {
                risks.Add(program.Risk);
            }
            risks.AddRange(services.Select(s => s.Risk));
        }
        Severity baseRisk;
        if (risks.Count > 0)
        {
            baseRisk = risks.Max();
        }
        else if (portOrRange is not null)
        {
            baseRisk = portOrRange.Risk;
            if (thirdParty)
            {
                baseRisk = EnumText.Max(baseRisk, Severity.Medium);
            }
        }
        else
        {
            baseRisk = thirdParty ? Severity.Medium : Severity.Low;
        }

        string label, explain;
        if (g.Pid == 4)
        {
            label = exact is not null ? $"Windows {exact.Name}" : $"A Windows kernel listener on port {g.Port}";
            explain = exact is not null ? exact.Explain : "Windows itself (the System process) listens here.";
        }
        else if (program is not null)
        {
            label = Capitalize(program.Description);
            explain = program.Explain;
        }
        else if (services.Count > 0)
        {
            label = $"Windows service: {services[0].Display}";
            explain = services[0].Description + (exact is not null ? $" {exact.Explain}" : "");
        }
        else if (exact is not null)
        {
            label = $"{(g.Process.Length > 0 ? g.Process : "A program")} ({exact.Name})";
            explain = exact.Explain;
        }
        else
        {
            label = g.Process.Length > 0 ? g.Process : $"An unknown program (PID {g.Pid})";
            explain = portOrRange is not null ? portOrRange.Summary : "SimplySec does not know this program.";
        }

        if (program is not null || thirdParty)
        {
            return new Identity(label, explain, baseRisk, program, portOrRange, thirdParty, "program", g.Exe.Length > 0 ? g.Exe : g.Process);
        }
        return new Identity(label, explain, baseRisk, program, portOrRange, thirdParty, "port", $"{g.Protocol}/{g.Port}");
    }

    // ------------------------------------------------------------------ fixes

    private static string RuleName(string fix) => $"SimplySec:{fix}:{Ambient.RuleToken()}";

    private static string Description(string why)
    {
        var today = Ambient.LocalNow.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        return $"Added by SimplySec on {today}: {why}. Undo it in SimplySec > Changes.";
    }

    private static JsonObject BlockRule(string fix, string why, Action<FirewallRule> configure)
    {
        var rule = new FirewallRule
        {
            Name = RuleName(fix),
            Action = "block",
            Direction = "in",
            Enabled = true,
            Grouping = Group,
            Description = Description(why),
        };
        configure(rule);
        return rule.ToJson();
    }

    public static List<ActionSpec> BuildBlockProgram(JsonObject p, bool publicOnly)
    {
        var exe = S(p["exe"]);
        var label = S(GetOr(p, "label", JsonValue.Create(NtPath.Basename(exe))));
        var where = publicOnly ? "Public networks" : "every network";
        var fix = publicOnly ? "block_program_public" : "block_program";
        var rule = BlockRule(fix, $"stop other devices on {where} connecting to {label}", r =>
        {
            r.Application = exe;
            r.Protocol = 256;
            r.Profiles = publicOnly ? (int)Profile.Public : EnumText.AllProfilesMask;
        });
        return [new ActionSpec("firewall.add_rule", new JsonObject { ["rule"] = rule },
            $"Add firewall rule '{S(rule["name"])}' that blocks incoming connections to {label} ({exe}) on {where}.")];
    }

    public static List<ActionSpec> BuildBlockPort(JsonObject p, bool publicOnly)
    {
        var proto = S(p["protocol"]);
        var port = Js.Int(p["port"]);
        var label = S(GetOr(p, "label", JsonValue.Create($"port {port}")));
        var where = publicOnly ? "Public networks" : "every network";
        var fix = publicOnly ? "block_port_public" : "block_port";
        var rule = BlockRule(fix, $"stop other devices on {where} connecting to {label} ({PyStr.Upper(proto)} {port})", r =>
        {
            r.Protocol = proto == "tcp" ? 6 : 17;
            r.LocalPorts = port.ToString(System.Globalization.CultureInfo.InvariantCulture);
            r.Profiles = publicOnly ? (int)Profile.Public : EnumText.AllProfilesMask;
        });
        return [new ActionSpec("firewall.add_rule", new JsonObject { ["rule"] = rule },
            $"Add firewall rule '{S(rule["name"])}' that blocks incoming {PyStr.Upper(proto)} port {port} ({label}) on {where}.")];
    }

    public static List<FixWarning> PublicNetworkWarning(ScanContext ctx, JsonObject p)
    {
        var output = new List<FixWarning>();
        foreach (var iface in ctx.CurrentPublicNetworks())
        {
            var name = iface.NetworkName.Length > 0 ? iface.NetworkName : iface.Alias;
            output.Add(new FixWarning
            {
                Text = $"Your {iface.Alias} connection ('{name}') is set to Public, so this also blocks devices on that network, including your own phone or other PCs. If this is your home network, mark it Private first (this can be undone too).",
                OfferFix = "network.mark_private",
                OfferParams = new JsonObject { ["index"] = iface.Index, ["alias"] = iface.Alias, ["name"] = name },
                OfferLabel = $"Mark '{name}' as a Private (home) network first",
            });
        }
        return output;
    }

    public static readonly FixDef FixBlockProgram = new()
    {
        Id = "exposure.block_program",
        Label = "Only this PC",
        Description = "Adds a firewall rule that blocks other devices from connecting to this program on every network. Programs on this PC can still use it.",
        MightBreak = "Phones, other PCs and VPN devices can no longer connect to this program.",
        Build = p => BuildBlockProgram(p, publicOnly: false),
        Disruptive = true,
    };

    public static readonly FixDef FixBlockProgramPublic = new()
    {
        Id = "exposure.block_program_public",
        Label = "Home network or VPN only",
        Description = "Adds a firewall rule that blocks this program on Public networks. Private (home) networks and your VPN keep working. The original allow rule is not touched.",
        MightBreak = "Devices on networks marked Public can no longer connect to this program.",
        Build = p => BuildBlockProgram(p, publicOnly: true),
        Disruptive = true,
        Warnings = PublicNetworkWarning,
    };

    public static readonly FixDef FixBlockPort = new()
    {
        Id = "exposure.block_port",
        Label = "Block this port on all networks",
        Description = "Adds a firewall rule that blocks incoming connections to this port on every network.",
        MightBreak = "Any device that uses this service on this PC (for example file sharing or casting) stops working.",
        Build = p => BuildBlockPort(p, publicOnly: false),
        Disruptive = true,
    };

    public static readonly FixDef FixBlockPortPublic = new()
    {
        Id = "exposure.block_port_public",
        Label = "Block this port on Public networks",
        Description = "Adds a firewall rule that blocks incoming connections to this port on Public networks only.",
        MightBreak = "Devices on networks marked Public can no longer use this service on this PC.",
        Build = p => BuildBlockPort(p, publicOnly: true),
        Disruptive = true,
        Warnings = PublicNetworkWarning,
    };

    public static readonly FixDef FixBlockProgramsPublic = new()
    {
        Id = "exposure.block_programs_public",
        Label = "Home network or VPN only (all listed)",
        Description = "Adds one block rule per program for Public networks. Private (home) networks and your VPN keep working; the original allow rules are not touched.",
        MightBreak = "These programs can no longer accept connections from devices on networks marked Public.",
        Build = p =>
        {
            var specs = new List<ActionSpec>();
            foreach (var exe in Js.Get(p, "exes") as JsonArray ?? [])
            {
                var path = S(exe);
                specs.AddRange(BuildBlockProgram(new JsonObject { ["exe"] = path, ["label"] = NtPath.Basename(path) }, publicOnly: true));
            }
            return specs;
        },
        Disruptive = true,
        Warnings = PublicNetworkWarning,
    };

    private static bool AllowAddRule(JsonObject p)
    {
        var rule = Js.Truthy(Js.Get(p, "rule")) ? Js.Get(p, "rule") : new JsonObject();
        var remote = GetOr(rule, "remote_addresses", JsonValue.Create("*"));
        return S(GetOr(rule, "name", JsonValue.Create(""))).StartsWith("SimplySec:", StringComparison.Ordinal)
               && Js.PyEquals(Js.Get(rule, "grouping"), JsonValue.Create(Group))
               && Js.PyEquals(Js.Get(rule, "action"), JsonValue.Create("block"))
               && Js.PyEquals(Js.Get(rule, "direction"), JsonValue.Create("in"))
               && Js.IsBool(Js.Get(rule, "enabled")) && Js.Get(rule, "enabled")!.GetValue<bool>()
               && (Js.PyEquals(remote, JsonValue.Create("")) || Js.PyEquals(remote, JsonValue.Create("*")))
               && !Js.Truthy(Js.Get(rule, "local_user_authorized"))
               && !Js.Truthy(Js.Get(rule, "local_app_package_id"));
    }

    // ------------------------------------------------------------------ detection

    private sealed class Subject(Identity ident)
    {
        public Identity Ident { get; } = ident;
        public List<PortGroup> Groups { get; } = [];
        public List<FirewallRule> Rules { get; } = [];
    }

    private static string SubjectId(Identity ident) =>
        ident.SubjectKind == "program"
            ? $"exposure.program:{PyStr.Lower(NtPath.Basename(ident.Subject))}"
            : $"exposure.port:{ident.Subject}";

    /// <summary>Enabled inbound allow rules for non-Windows programs that include the Public profile.</summary>
    private static OrderedDictionary<string, List<FirewallRule>> PublicAllowRules(ScanContext ctx)
    {
        var output = new OrderedDictionary<string, List<FirewallRule>>(StringComparer.Ordinal);
        foreach (var rule in ctx.Firewall.Rules)
        {
            if (rule.Direction != "in" || !rule.Enabled || rule.Action != "allow")
            {
                continue;
            }
            if ((rule.ProfileMask & (int)Profile.Public) == 0 || rule.Grouping == Group)
            {
                continue;
            }
            var app = Evaluator.NormalizeAppPath(rule.Application, ctx.Env);
            if (app.Length == 0 || app == "system" || ctx.IsWindowsBinary(app))
            {
                continue;
            }
            if (Evaluator.RequiresAuthentication(rule))
            {
                continue;
            }
            var (remote, _) = Evaluator.AddressSet(rule.RemoteAddresses, 4, new Dictionary<string, Net.AddrSet>(StringComparer.Ordinal));
            var spec = PyStr.Strip(string.IsNullOrEmpty(rule.RemoteAddresses) ? "*" : rule.RemoteAddresses);
            if (remote.IsEmpty && spec is not ("" or "*"))
            {
                continue;
            }
            if (!output.TryGetValue(app, out var list))
            {
                list = [];
                output[app] = list;
            }
            list.Add(rule);
        }
        return output;
    }

    private static List<(string, string)> Details(Subject subj, ScanContext ctx)
    {
        var details = new List<(string, string)>();
        if (subj.Groups.Count > 0)
        {
            var ports = string.Join(", ", subj.Groups.Select(g => $"{PyStr.Upper(g.Protocol)} {g.Port}").Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal));
            details.Add(("Ports", ports));
            var g0 = subj.Groups[0];
            details.Add(("Program", g0.Exe.Length > 0 ? g0.Exe : g0.Process.Length > 0 ? g0.Process : "System (Windows kernel)"));
            details.Add(("Process ID", string.Join(", ", subj.Groups.Select(g => g.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture)).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))));
            var services = subj.Groups.SelectMany(g => g.Services ?? []).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();
            if (services.Count > 0)
            {
                details.Add(("Services", string.Join(", ", services)));
            }
            var sig = ctx.Signature(g0.Exe);
            if (sig is not null && g0.Exe.Length > 0)
            {
                details.Add(("Signature", $"{sig.Status}{(sig.Publisher.Length > 0 ? " – " + sig.Publisher : "")}"));
            }
            var addrs = subj.Groups.SelectMany(g => g.Addresses).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal);
            details.Add(("Listening on", string.Join(", ", addrs)));
            foreach (var g in subj.Groups)
            {
                foreach (var e in g.Exposures)
                {
                    foreach (var ie in e.PerInterface)
                    {
                        details.Add(($"{PyStr.Upper(g.Protocol)} {g.Port} via {ie.Interface} ({ie.Profile.Label()})", ie.Reason));
                    }
                }
            }
        }
        if (subj.Rules.Count > 0)
        {
            var names = subj.Rules.Select(r => r.Name).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal);
            details.Add(("Firewall rules allowing it on Public networks", string.Join(", ", names.Select(n => $"'{n}'"))));
        }
        var ruleNames = subj.Groups
            .SelectMany(g => g.Exposures).SelectMany(e => e.PerInterface)
            .SelectMany(ie => ie.AllowRules.Concat(ie.BlockRules))
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();
        if (ruleNames.Count > 0)
        {
            details.Add(("Firewall rules involved", string.Join(", ", ruleNames.Select(n => $"'{n}'"))));
        }
        return details.Distinct().ToList();
    }

    /// <summary>Risk of one reachable port group (used by the Open ports table) and its finding id.</summary>
    public static (Severity, string) ExposureSeverityForGroup(PortGroup g, ScanContext ctx)
    {
        var ident = Identify(g, ctx);
        var width = Scoring.ExposureWidth(g.Exposures);
        var sig = ctx.Signature(g.Exe);
        var unsigned = ident.ThirdParty && ident.Program is null && sig is not null && !sig.Signed;
        var writable = ident.ThirdParty && ident.Program is null && IsUserWritable(g.Exe, ctx.Env);
        var sev = Scoring.ExposureSeverity(ident.Base, width, unsigned, writable, UserConfigured(ident.Program, ctx.Env));
        return (sev, SubjectId(ident));
    }

    public static List<Finding> Run(ScanContext ctx)
    {
        var subjects = new OrderedDictionary<string, Subject>(StringComparer.Ordinal);
        var protectedGroups = new List<PortGroup>();
        var uncertain = new List<PortGroup>();

        foreach (var g in ctx.Groups)
        {
            var verdicts = g.Exposures.Select(e => e.Verdict).ToHashSet();
            if (verdicts.Contains(Verdict.Reachable))
            {
                var ident = Identify(g, ctx);
                var sid = SubjectId(ident);
                if (!subjects.TryGetValue(sid, out var subj))
                {
                    subj = new Subject(ident);
                    subjects[sid] = subj;
                }
                subj.Groups.Add(g);
            }
            else if (verdicts.Contains(Verdict.Uncertain))
            {
                uncertain.Add(g);
            }
            else if (verdicts.Contains(Verdict.Blocked))
            {
                protectedGroups.Add(g);
            }
        }

        // Rules that allow non-Windows programs on Public networks (even when not running now).
        var unknownRules = new OrderedDictionary<string, List<FirewallRule>>(StringComparer.Ordinal);
        foreach (var (app, rules) in PublicAllowRules(ctx))
        {
            var baseName = NtPath.Basename(app);
            var sid = $"exposure.program:{baseName}";
            if (subjects.TryGetValue(sid, out var existing))
            {
                existing.Rules.AddRange(rules);
                continue;
            }
            var program = ctx.Kb.Program(baseName);
            if (program is null)
            {
                unknownRules[app] = rules;
                continue;
            }
            var ident = new Identity(Capitalize(program.Description), program.Explain, program.Risk, program, null, true, "program", rules[0].Application);
            var s = new Subject(ident);
            s.Rules.AddRange(rules);
            subjects[$"exposure.rule:{baseName}"] = s;
        }

        var findings = new List<Finding>();
        foreach (var (sid, subj) in subjects)
        {
            var ident = subj.Ident;
            var listening = subj.Groups.Count > 0;
            var exposures = subj.Groups.SelectMany(g => g.Exposures).ToList();
            var width = listening ? Scoring.ExposureWidth(exposures) : Scoring.WidthPublicAny;
            var exe = listening ? subj.Groups[0].Exe : Evaluator.NormalizeAppPath(ident.Subject, ctx.Env);
            var sig = ctx.Signature(exe);
            var unsigned = ident.ThirdParty && ident.Program is null && sig is not null && !sig.Signed;
            var writable = ident.ThirdParty && ident.Program is null && IsUserWritable(exe, ctx.Env);
            var intent = UserConfigured(ident.Program, ctx.Env);

            Severity sev;
            if (listening)
            {
                sev = Scoring.ExposureSeverity(ident.Base, width, unsigned, writable, intent);
            }
            else if (!ctx.FileExists(exe) || intent || ident.Base <= Severity.Low)
            {
                sev = Severity.Info;
            }
            else
            {
                sev = Severity.Low;
            }

            if (listening && !ident.ThirdParty && sev < Severity.Medium)
            {
                continue; // low-risk Windows listeners: shown in the Open ports table only
            }

            var reachText = Scoring.WidthLabels[width];
            string title;
            if (intent)
            {
                title = $"{ident.Label} is reachable from other devices – you set this up";
            }
            else if (!listening)
            {
                title = $"{ident.Label} is allowed through the firewall on Public networks";
            }
            else if (unsigned)
            {
                title = $"{ident.Label} accepts connections and is not digitally signed";
            }
            else if (writable)
            {
                title = $"{ident.Label} accepts connections from a folder any program can change";
            }
            else
            {
                title = $"{ident.Label} can be reached by {reachText}";
            }

            var whatParts = new List<string> { ident.Explain };
            if (listening)
            {
                var reasons = exposures.SelectMany(e => e.PerInterface).Where(ie => ie.Verdict == Verdict.Reachable).Select(ie => ie.Reason).ToList();
                if (reasons.Count > 0)
                {
                    whatParts.Add(reasons[0]);
                }
            }
            else
            {
                whatParts.Add("A firewall rule lets devices on Public networks (cafés, hotels, airports) connect to it whenever it runs. It is not listening right now.");
                if (!ctx.FileExists(exe))
                {
                    whatParts.Add("The program no longer exists at that location; the rule is a leftover.");
                }
            }
            if (intent && ident.Program is not null)
            {
                var value = ctx.Env.TryGetValue(PyStr.Upper(ident.Program.IntentEnv), out var ev) ? ev : "";
                whatParts.Add($"You set {ident.Program.IntentEnv}={value}, so this looks deliberate. Choose Keep if you need it, or limit who can reach it.");
            }
            if (unsigned)
            {
                whatParts.Add("The program has no valid digital signature, so its publisher can't be confirmed.");
            }
            if (writable)
            {
                whatParts.Add("It runs from a user folder, where other programs could replace it.");
            }

            var fixes = new List<FixOption>();
            var reachablePublic = width >= Scoring.WidthPublicSubnet;
            if (ident.SubjectKind == "program" && exe.Length > 0)
            {
                var prm = new JsonObject
                {
                    ["exe"] = exe,
                    ["label"] = ident.Program is not null ? ident.Program.Name : NtPath.Basename(exe),
                };
                if (reachablePublic || !listening)
                {
                    fixes.Add(FixBlockProgramPublic.Option(prm));
                }
                fixes.Add(FixBlockProgram.Option(prm));
            }
            else
            {
                var g0 = subj.Groups[0];
                var prm = new JsonObject { ["protocol"] = g0.Protocol, ["port"] = g0.Port, ["label"] = ident.Label };
                if (reachablePublic)
                {
                    fixes.Add(FixBlockPortPublic.Option(prm));
                }
                fixes.Add(FixBlockPort.Option(prm));
            }
            if (ident.Port is PortInfo pi)
            {
                foreach (var fid in pi.FixIds)
                {
                    if (!fid.StartsWith("exposure.", StringComparison.Ordinal) && !fixes.Any(f => f.FixId == fid))
                    {
                        var topic = ctx.FixOption(fid);
                        if (topic is not null)
                        {
                            fixes.Insert(0, topic);
                        }
                    }
                }
            }

            var finding = NewFinding(sid, CheckId, Area, title, sev,
                string.Join(" ", whatParts.Where(p => p.Length > 0)),
                Details(subj, ctx), fixes,
                ident.Port is not null ? ident.Port.Advice : "");
            finding.KeepKey = $"keep:{sid}";
            finding.Width = width;
            finding.UserConfigured = intent;
            if (ctx.Accepted.TryGetValue(finding.KeepKey, out var acceptedWidth) && acceptedWidth >= width)
            {
                finding.Status = FindingStatus.Accepted;
            }
            findings.Add(finding);
        }

        if (unknownRules.Count > 0)
        {
            findings.Add(PublicRulesFinding(unknownRules, ctx));
        }

        if (uncertain.Count > 0)
        {
            var details = uncertain.Select(g => (
                $"{PyStr.Upper(g.Protocol)} {g.Port} – {(g.Process.Length > 0 ? g.Process : "PID " + g.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture))}",
                g.Exposures.FirstOrDefault(e => e.Verdict == Verdict.Uncertain)?.Reason ?? "")).ToList();
            findings.Add(NewFinding("exposure.uncertain", CheckId, Area,
                $"{uncertain.Count} listening port(s) could not be fully checked", Severity.Info,
                "Some firewall rules depend on details SimplySec could not read or evaluate (for example which user runs a program, or ports Windows assigns at runtime). These ports are reported as Uncertain, never as protected. Technical details say why for each.",
                details));
        }
        if (protectedGroups.Count > 0)
        {
            var details = protectedGroups.Select(g => (
                $"{PyStr.Upper(g.Protocol)} {g.Port} – {(g.Process.Length > 0 ? g.Process : "PID " + g.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture))}",
                g.Exposures.FirstOrDefault(e => e.Verdict == Verdict.Blocked)?.Reason ?? "")).ToList();
            var f = NewFinding("exposure.protected", CheckId, Area,
                $"{protectedGroups.Count} listening port(s) are protected by the firewall", Severity.Info,
                "These programs listen for connections, but the firewall stops other devices from reaching them. Shown for transparency; nothing to do.",
                details);
            f.Status = FindingStatus.Info;
            findings.Add(f);
        }
        return findings;
    }

    private static Finding PublicRulesFinding(OrderedDictionary<string, List<FirewallRule>> unknown, ScanContext ctx)
    {
        var present = unknown.Where(kv => ctx.FileExists(kv.Key)).ToList();
        var presentKeys = present.Select(kv => kv.Key).ToHashSet(StringComparer.Ordinal);
        var leftovers = unknown.Keys.Where(k => !presentKeys.Contains(k)).Order(StringComparer.Ordinal).ToList();
        var details = new List<(string, string)>();
        var risky = 0;
        foreach (var (app, rules) in present.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            var sig = ctx.Signature(app);
            var notes = new List<string>();
            if (IsUserWritable(app, ctx.Env))
            {
                notes.Add("runs from a user folder");
            }
            if (sig is not null && !sig.Signed)
            {
                notes.Add("not signed");
            }
            else if (sig is not null && sig.Publisher.Length > 0)
            {
                notes.Add($"signed by {sig.Publisher}");
            }
            if (notes.Count >= 2 && notes.Contains("not signed"))
            {
                risky += 1;
            }
            var ruleNames = string.Join(", ", rules.Select(r => $"'{r.Name}'").Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal));
            details.Add((rules[0].Application, $"rules {ruleNames}" + (notes.Count > 0 ? $" – {string.Join("; ", notes)}" : "")));
        }
        foreach (var app in leftovers)
        {
            details.Add((app, "program no longer installed (leftover rule)"));
        }
        var count = present.Count;
        var f = NewFinding("exposure.public_rules", CheckId, Area,
            $"{count} other program(s) are allowed through the firewall on Public networks",
            count > 0 ? (risky > 0 ? Severity.Medium : Severity.Low) : Severity.Info,
            "Windows rules let these programs accept connections on Public networks (cafés, hotels, airports) whenever they run. None of them is listening right now. Usually this comes from clicking 'Allow' on a firewall prompt or from an installer. " +
            (risky > 0 ? $"{risky} of them run unsigned from a user folder, which deserves a closer look. " : "") +
            "Limiting them to home networks adds block rules for Public networks; the original rules stay.",
            details,
            count > 0 ? [FixBlockProgramsPublic.Option(new JsonObject { ["exes"] = Js.StrArray(present.Select(kv => kv.Key).Order(StringComparer.Ordinal)) })] : []);
        f.KeepKey = "keep:exposure.public_rules";
        f.Width = count;
        if (ctx.Accepted.TryGetValue(f.KeepKey, out var accepted) && accepted >= count)
        {
            f.Status = FindingStatus.Accepted;
        }
        return f;
    }

    public static readonly Check Definition = new()
    {
        Id = CheckId,
        Area = Area,
        Run = Run,
        Fixes = [FixBlockProgram, FixBlockProgramPublic, FixBlockPort, FixBlockPortPublic, FixBlockProgramsPublic],
        Allows = [new Allow("firewall.add_rule", AllowAddRule)],
    };
}
