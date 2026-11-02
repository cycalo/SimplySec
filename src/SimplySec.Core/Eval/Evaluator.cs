using System.Text.RegularExpressions;
using SimplySec.Core.Compat;
using SimplySec.Core.Model;
using SimplySec.Core.Net;
using SimplySec.Core.Security;

namespace SimplySec.Core.Eval;

/// <summary>Context for one evaluation: interfaces, environment and the local subnets.</summary>
public sealed class EvalContext
{
    public List<NetInterface> Interfaces { get; }
    public IReadOnlyDictionary<string, string> Env { get; }
    public Dictionary<int, AddrSet> LocalSubnets { get; }

    public EvalContext(List<NetInterface> interfaces, IReadOnlyDictionary<string, string> env, Dictionary<int, AddrSet>? localSubnets = null)
    {
        Interfaces = interfaces;
        Env = env;
        if (localSubnets is { Count: > 0 })
        {
            LocalSubnets = localSubnets;
            return;
        }
        var subnets = new Dictionary<int, AddrSet> { [4] = AddrSet.Empty(4), [6] = AddrSet.Empty(6) };
        foreach (var iface in interfaces)
        {
            if (!iface.Up)
            {
                continue;
            }
            foreach (var ipi in iface.IpInterfaces())
            {
                subnets[ipi.Family] = subnets[ipi.Family].Union(AddrSet.FromNetwork(ipi.Network));
            }
        }
        foreach (var fam in new[] { 4, 6 })
        {
            subnets[fam] = subnets[fam].Subtract(AddrSet.Loopback(fam));
        }
        LocalSubnets = subnets;
    }
}

public sealed class PortSpec
{
    public bool Any { get; set; }
    public List<(int Lo, int Hi)> Ranges { get; } = [];
    public List<string> Keywords { get; } = [];
}

public sealed class CompiledRule
{
    public required FirewallRule Rule { get; init; }
    public required string App { get; init; }
    public required PortSpec Ports { get; init; }
    public UserCondition? User { get; init; }
    public int ProfileMask { get; init; }
    public string Name => Rule.Name;
}

/// <summary>
/// Who can reach a listening port? A pure model of Windows Firewall inbound filtering.
/// Port of <c>core/exposure.py</c>; behaviour and wording must stay identical.
/// </summary>
public static partial class Evaluator
{
    public const int DynamicRpcStart = 49152;

    public static bool? TriAnd(IEnumerable<bool?> values)
    {
        bool? result = true;
        foreach (var v in values)
        {
            if (v == false)
            {
                return false;
            }
            if (v is null)
            {
                result = null;
            }
        }
        return result;
    }

    // ------------------------------------------------------------------ paths

    [GeneratedRegex("%([^%]+)%")]
    private static partial Regex EnvVar();

    public static string ExpandEnv(string path, IReadOnlyDictionary<string, string> env) =>
        EnvVar().Replace(path, m => env.TryGetValue(PyStr.Upper(m.Groups[1].Value), out var v) ? v : m.Value);

    /// <summary>Comparable form of a program path: env vars expanded, case folded, normalised.</summary>
    public static string NormalizeAppPath(string path, IReadOnlyDictionary<string, string> env)
    {
        var p = PyStr.Strip(PyStr.Strip(path), '"');
        if (p.Length == 0)
        {
            return "";
        }
        if (PyStr.Lower(p) == "system")
        {
            return "system";
        }
        p = ExpandEnv(p, env).Replace('/', '\\');
        if (p.StartsWith("\\??\\", StringComparison.Ordinal))
        {
            p = p[4..];
        }
        return PyStr.Lower(NtPath.NormPath(p));
    }

    // ------------------------------------------------------------------ compiled rules

    [GeneratedRegex(@"^\d+$")]
    private static partial Regex Digits();

    [GeneratedRegex(@"^\d+-\d+$")]
    private static partial Regex DigitRange();

    public static PortSpec ParsePorts(string? spec)
    {
        var output = new PortSpec();
        var text = PyStr.Strip(spec);
        if (text is "" or "*")
        {
            output.Any = true;
            return output;
        }
        foreach (var raw in text.Split(','))
        {
            var token = PyStr.Strip(raw);
            if (token.Length == 0)
            {
                continue;
            }
            if (token == "*")
            {
                output.Any = true;
            }
            else if (IsAsciiDigits(token) && Digits().IsMatch(token))
            {
                var n = ParseBig(token);
                output.Ranges.Add((n, n));
            }
            else if (DigitRange().IsMatch(token) && token.All(c => c == '-' || char.IsAsciiDigit(c)))
            {
                var bits = token.Split('-');
                output.Ranges.Add((ParseBig(bits[0]), ParseBig(bits[1])));
            }
            else
            {
                output.Keywords.Add(PyStr.Lower(token));
            }
        }
        return output;
    }

    private static bool IsAsciiDigits(string s) => s.All(char.IsAsciiDigit);

    private static int ParseBig(string s) =>
        int.TryParse(s, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var v) ? v : int.MaxValue;

    public static List<CompiledRule> CompileRules(IEnumerable<FirewallRule> rules, IReadOnlyDictionary<string, string> env)
    {
        var compiled = new List<CompiledRule>();
        foreach (var r in rules)
        {
            if (r.Direction != "in" || !r.Enabled)
            {
                continue;
            }
            compiled.Add(new CompiledRule
            {
                Rule = r,
                App = NormalizeAppPath(r.Application, env),
                Ports = ParsePorts(r.LocalPorts),
                User = r.LocalUserAuthorized.Length > 0 ? Sddl.ParseUserCondition(r.LocalUserAuthorized) : null,
                ProfileMask = r.ProfileMask,
            });
        }
        return compiled;
    }

    // ------------------------------------------------------------------ matching

    private static bool? MatchProtocol(FirewallRule rule, Listener lst)
    {
        if (rule.Protocol == 256)
        {
            return true;
        }
        return (rule.Protocol == 6 && lst.Protocol == "tcp") || (rule.Protocol == 17 && lst.Protocol == "udp");
    }

    private static bool? KeywordPort(string kw, Listener lst)
    {
        bool tcp = lst.Protocol == "tcp", udp = lst.Protocol == "udp";
        var port = lst.Port;
        switch (kw)
        {
            case "rpc":
                if (!tcp || port == 135)
                {
                    return false;
                }
                return port >= DynamicRpcStart ? true : null;
            case "rpc-epmap":
                return tcp && port == 135;
            case "iphttps":
                return tcp && port == 443;
            case "teredo":
            case "ply2disc":
                return udp ? null : false;
            case "mdns":
                return udp && port == 5353;
            default:
                return null;
        }
    }

    private static bool? LocalPort(CompiledRule cr, Listener lst)
    {
        var spec = cr.Ports;
        if (spec.Any)
        {
            return true;
        }
        if (spec.Ranges.Any(r => r.Lo <= lst.Port && lst.Port <= r.Hi))
        {
            return true;
        }
        var results = spec.Keywords.Select(k => KeywordPort(k, lst)).ToList();
        if (results.Any(r => r == true))
        {
            return true;
        }
        return results.Any(r => r is null) ? null : false;
    }

    private static bool? Application(CompiledRule cr, Listener lst, IReadOnlyDictionary<string, string> env)
    {
        if (cr.App.Length == 0)
        {
            return true;
        }
        if (cr.App == "system")
        {
            return lst.Pid == 4;
        }
        if (lst.Pid == 4)
        {
            return false;
        }
        if (lst.Exe.Length == 0)
        {
            return null;
        }
        return NormalizeAppPath(lst.Exe, env) == cr.App;
    }

    private static bool? Service(FirewallRule rule, Listener lst)
    {
        var svc = PyStr.Strip(rule.Service);
        if (svc.Length == 0)
        {
            return true;
        }
        if (lst.Services is null)
        {
            return null;
        }
        if (svc == "*")
        {
            return lst.Services.Count > 0;
        }
        var lower = PyStr.Lower(svc);
        return lst.Services.Any(s => PyStr.Lower(s) == lower);
    }

    private static bool? Interface(FirewallRule rule, NetInterface iface)
    {
        if (rule.Interfaces.Count > 0)
        {
            var names = rule.Interfaces.Select(PyStr.Lower).ToHashSet(StringComparer.Ordinal);
            if (!(names.Contains(PyStr.Lower(iface.Alias)) || names.Contains(PyStr.Lower(iface.Description))))
            {
                return false;
            }
        }
        var typesText = string.IsNullOrEmpty(rule.InterfaceTypes) ? "All" : rule.InterfaceTypes;
        var types = typesText.Split(',').Select(t => PyStr.Lower(PyStr.Strip(t))).ToHashSet(StringComparer.Ordinal);
        if (types.Contains("all") || types.All(t => t.Length == 0))
        {
            return true;
        }
        string? wanted = iface.Kind switch
        {
            InterfaceKind.Ethernet => "lan",
            InterfaceKind.Virtual => "lan",
            InterfaceKind.Wifi => "wireless",
            _ => null,
        };
        if (wanted is null)
        {
            return null;
        }
        return types.Contains(wanted);
    }

    internal static Dictionary<string, AddrSet> AddressContext(NetInterface iface, int family, EvalContext ctx)
    {
        AddrSet FromIps(List<string> ips)
        {
            var s = AddrSet.Empty(family);
            foreach (var ip in ips)
            {
                var lit = AddrSet.ParseLiteral(ip);
                if (lit is not null && lit.Family == family)
                {
                    s = s.Union(lit);
                }
            }
            return s;
        }
        return new Dictionary<string, AddrSet>(StringComparer.Ordinal)
        {
            ["localsubnet"] = ctx.LocalSubnets.TryGetValue(family, out var ls) ? ls : AddrSet.Empty(family),
            ["dns"] = FromIps(iface.DnsServers),
            ["dhcp"] = FromIps(iface.DhcpServers),
            ["defaultgateway"] = FromIps(iface.Gateways),
        };
    }

    /// <summary>Parse a firewall address list. Returns (resolved set, fully resolved).</summary>
    public static (AddrSet Set, bool Fully) AddressSet(string? spec, int family, IReadOnlyDictionary<string, AddrSet> keywords)
    {
        var text = PyStr.Strip(spec);
        if (text is "" or "*")
        {
            return (AddrSet.Everything(family), true);
        }
        var result = AddrSet.Empty(family);
        var resolved = true;
        foreach (var raw in text.Split(','))
        {
            var token = PyStr.Strip(raw);
            if (token.Length == 0)
            {
                continue;
            }
            if (token == "*")
            {
                return (AddrSet.Everything(family), true);
            }
            var lit = AddrSet.ParseLiteral(token);
            if (lit is not null)
            {
                if (lit.Family == family)
                {
                    result = result.Union(lit);
                }
                continue;
            }
            if (keywords.TryGetValue(PyStr.Lower(token), out var kw))
            {
                result = result.Union(kw);
            }
            else
            {
                resolved = false;
            }
        }
        return (result, resolved);
    }

    private static bool? LocalAddress(FirewallRule rule, Listener lst, NetInterface iface, EvalContext ctx)
    {
        var spec = PyStr.Strip(rule.LocalAddresses);
        if (spec is "" or "*")
        {
            return true;
        }
        var fam = lst.Family;
        var (allowed, fully) = AddressSet(spec, fam, AddressContext(iface, fam, ctx));
        List<string> localIps = lst.IsWildcard
            ? iface.IpInterfaces().Where(i => i.Family == fam).Select(i => i.Ip.ToString()).ToList()
            : [lst.Address];
        if (localIps.Any(allowed.ContainsIp))
        {
            return true;
        }
        return fully ? false : null;
    }

    private static bool? Users(CompiledRule cr, Listener lst)
    {
        var rule = cr.Rule;
        var results = new List<bool?>();
        if (cr.User is not null)
        {
            results.Add(cr.User.Decide(lst.UserSid));
        }
        if (rule.LocalUserOwner.Length > 0)
        {
            results.Add(lst.UserSid is null ? null : PyStr.Upper(lst.UserSid) == PyStr.Upper(rule.LocalUserOwner));
        }
        if (rule.LocalAppPackageId.Length > 0)
        {
            var pkg = PyStr.Upper(rule.LocalAppPackageId);
            if (lst.PackageSid is null)
            {
                results.Add(null);
            }
            else if (lst.PackageSid.Length == 0)
            {
                results.Add(false);
            }
            else
            {
                results.Add(pkg == "S-1-15-2-1" || PyStr.Upper(lst.PackageSid) == pkg);
            }
        }
        else if (rule.LocalUserOwner.Length > 0 && rule.Application.Length == 0)
        {
            // Store-app capability rules carry an owner and only apply inside that app's sandbox.
            if (lst.PackageSid is null || lst.PackageSid.Length > 0)
            {
                results.Add(null);
            }
            else
            {
                results.Add(false);
            }
        }
        return TriAnd(results);
    }

    public static bool? RuleMatches(CompiledRule cr, Listener lst, NetInterface iface, EvalContext ctx)
    {
        var rule = cr.Rule;
        if (rule.TrustTuples.Count > 0)
        {
            return false;
        }
        var results = new List<bool?>(7);
        Func<bool?>[] checks =
        [
            () => MatchProtocol(rule, lst),
            () => LocalPort(cr, lst),
            () => Application(cr, lst, ctx.Env),
            () => Service(rule, lst),
            () => Interface(rule, iface),
            () => LocalAddress(rule, lst, iface, ctx),
            () => Users(cr, lst),
        ];
        foreach (var fn in checks)
        {
            var r = fn();
            if (r == false)
            {
                return false;
            }
            results.Add(r);
        }
        return TriAnd(results);
    }

    public static readonly IReadOnlyDictionary<string, string> UncertainWhy = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["port"] = "a port that Windows assigns at runtime (keyword {kw})",
        ["program"] = "the program's path, which could not be read",
        ["service"] = "the services this process hosts, which could not be read",
        ["interface"] = "the adapter type, which Windows does not expose for this adapter",
        ["address"] = "an address keyword SimplySec does not model",
        ["user"] = "which user or Store app runs this program, which could not be read",
    };

    private static readonly HashSet<string> NeedsAdminWhy = new(StringComparer.Ordinal) { "program", "service", "user" };

    public static string WhyUncertain(CompiledRule cr, Listener lst, NetInterface iface, EvalContext ctx)
    {
        (string Code, Func<bool?> Fn)[] checks =
        [
            ("port", () => LocalPort(cr, lst)),
            ("program", () => Application(cr, lst, ctx.Env)),
            ("service", () => Service(cr.Rule, lst)),
            ("interface", () => Interface(cr.Rule, iface)),
            ("address", () => LocalAddress(cr.Rule, lst, iface, ctx)),
            ("user", () => Users(cr, lst)),
        ];
        foreach (var (code, fn) in checks)
        {
            if (fn() is null)
            {
                return code;
            }
        }
        return "address";
    }

    public static bool RequiresAuthentication(FirewallRule rule) =>
        rule.SecureFlags != 0 || rule.RemoteUserAuthorized.Length > 0 || rule.RemoteMachineAuthorized.Length > 0;

    // ------------------------------------------------------------------ evaluation

    internal static string QuoteNames(List<string> names, int limit = 3)
    {
        var uniq = new List<string>();
        foreach (var n in names)
        {
            if (!uniq.Contains(n))
            {
                uniq.Add(n);
            }
        }
        var shown = string.Join(", ", uniq.Take(limit).Select(n => $"'{n}'"));
        if (uniq.Count > limit)
        {
            shown += $" and {uniq.Count - limit} more";
        }
        return shown;
    }

    private static string Where(NetInterface iface)
    {
        if (iface.Kind == InterfaceKind.Vpn)
        {
            return $"devices on your {iface.Alias} network";
        }
        if (iface.Kind == InterfaceKind.Virtual)
        {
            return $"virtual machines on this PC ({iface.Alias})";
        }
        var prof = iface.EffectiveProfile.Label();
        var assumed = iface.Profile is null ? " (assumed: Windows has no profile for it)" : "";
        return $"devices on the {iface.Alias} network ({prof}{assumed})";
    }

    public static (Verdict, Scope) Classify(AddrSet eff, int family, EvalContext ctx)
    {
        if (eff.IsEmpty)
        {
            return (Verdict.Blocked, Scope.None);
        }
        var local = ctx.LocalSubnets.TryGetValue(family, out var l) ? l : AddrSet.Empty(family);
        if (eff.IsSubsetOf(local))
        {
            return (Verdict.Reachable, Scope.LocalSubnet);
        }
        var space = AddrSet.Everything(family).Subtract(AddrSet.Loopback(family));
        if (space.Subtract(local).IsSubsetOf(eff))
        {
            return (Verdict.Reachable, Scope.Anyone);
        }
        return (Verdict.Reachable, Scope.Specific);
    }

    public static InterfaceExposure EvaluateOnInterface(
        Listener lst, NetInterface iface, FirewallState fw, List<CompiledRule> rules, EvalContext ctx)
    {
        var prof = iface.EffectiveProfile;
        var b = new InterfaceExposure
        {
            Interface = iface.Alias,
            InterfaceKind = iface.Kind,
            Profile = prof,
            ProfileAssumed = iface.Profile is null,
            Verdict = Verdict.Uncertain,
            Scope = Scope.None,
        };
        if (!fw.Profiles.TryGetValue(prof, out var state))
        {
            b.Reason = $"The firewall settings for {prof.Label()} networks could not be read.";
            return b;
        }
        if (!state.Enabled)
        {
            b.Verdict = Verdict.Reachable;
            b.Scope = Scope.Anyone;
            b.Remote = ["any address"];
            b.Reason = $"Anyone who can reach {Where(iface)} can connect: the firewall is turned off for {prof.Label()} networks.";
            return b;
        }
        if (state.BlockAllInbound)
        {
            b.Verdict = Verdict.Blocked;
            b.Reason = $"Blocked on {iface.Alias}: the firewall blocks all incoming connections on {prof.Label()} networks.";
            return b;
        }

        var fam = lst.Family;
        var kw = AddressContext(iface, fam, ctx);
        var empty = AddrSet.Empty(fam);
        var everything = AddrSet.Everything(fam);
        AddrSet sureAllow = empty, maybeAllow = empty, sureBlock = empty, maybeBlock = empty;
        var allowNames = new List<string>();
        var blockNames = new List<string>();
        var maybeNames = new List<string>();
        var maybeWhy = new OrderedDictionary<string, string>(StringComparer.Ordinal);
        var authOnly = new List<string>();
        var edge = false;

        foreach (var cr in rules)
        {
            if ((cr.ProfileMask & (int)prof) == 0)
            {
                continue;
            }
            var m = RuleMatches(cr, lst, iface, ctx);
            if (m == false)
            {
                continue;
            }
            var rule = cr.Rule;
            if (m is null)
            {
                var code = WhyUncertain(cr, lst, iface, ctx);
                var keywords = cr.Ports.Keywords.Count > 0 ? string.Join(",", cr.Ports.Keywords) : "?";
                maybeWhy.TryAdd(code, UncertainWhy[code].Replace("{kw}", keywords, StringComparison.Ordinal));
            }
            var (remote, fully) = AddressSet(rule.RemoteAddresses, fam, kw);
            if (rule.Action == "allow")
            {
                if (RequiresAuthentication(rule))
                {
                    authOnly.Add(rule.Name);
                    continue;
                }
                if (m == true)
                {
                    sureAllow = sureAllow.Union(remote);
                    allowNames.Add(rule.Name);
                    if (rule.EdgeTraversal || rule.EdgeTraversalOptions == 1)
                    {
                        edge = true;
                    }
                    if (!fully)
                    {
                        maybeAllow = maybeAllow.Union(everything);
                        maybeNames.Add(rule.Name);
                        maybeWhy.TryAdd("address", UncertainWhy["address"]);
                    }
                }
                else
                {
                    maybeAllow = maybeAllow.Union(fully ? remote : everything);
                    maybeNames.Add(rule.Name);
                }
            }
            else
            {
                var rp = PyStr.Strip(string.IsNullOrEmpty(rule.RemotePorts) ? "*" : rule.RemotePorts);
                var partial = rp is not ("" or "*");
                if (m == true && !partial)
                {
                    sureBlock = sureBlock.Union(remote);
                    blockNames.Add(rule.Name);
                    if (!fully)
                    {
                        maybeBlock = maybeBlock.Union(everything);
                        maybeNames.Add(rule.Name);
                        maybeWhy.TryAdd("address", UncertainWhy["address"]);
                    }
                }
                else
                {
                    maybeBlock = maybeBlock.Union(fully ? remote : everything);
                    maybeNames.Add(rule.Name);
                }
            }
        }

        var space = everything.Subtract(AddrSet.Loopback(fam));
        AddrSet Effective(AddrSet allow, AddrSet block)
        {
            var start = !state.DefaultInboundBlock ? space : allow.Intersect(space);
            return start.Subtract(block);
        }

        var effMin = Effective(sureAllow, sureBlock.Union(maybeBlock));
        var effMax = Effective(sureAllow.Union(maybeAllow), sureBlock);
        var (vMin, sMin) = Classify(effMin, fam, ctx);
        var (vMax, sMax) = Classify(effMax, fam, ctx);

        b.AllowRules = allowNames.Distinct(StringComparer.Ordinal).ToList();
        b.BlockRules = blockNames.Distinct(StringComparer.Ordinal).ToList();
        b.UncertainRules = maybeNames.Distinct(StringComparer.Ordinal).ToList();
        b.EdgeTraversal = edge;
        var where = Where(iface);

        if (vMin == Verdict.Reachable)
        {
            b.Verdict = Verdict.Reachable;
            b.Scope = sMax;
            b.Remote = effMax.Describe();
            var because = !state.DefaultInboundBlock && allowNames.Count == 0
                ? $"the firewall's default for {prof.Label()} networks is to allow connections"
                : $"the firewall rule {QuoteNames(allowNames)} allows it";
            var who = sMax switch
            {
                Scope.Anyone => $"Anyone who can reach {where}",
                Scope.LocalSubnet => $"Only {where} on the same local subnet",
                Scope.Specific => $"Some addresses ({string.Join(", ", b.Remote)}) via {iface.Alias}",
                _ => throw new KeyNotFoundException(sMax.Value()),
            };
            b.Reason = $"{who} can connect: {because}.";
            if (sMin != sMax)
            {
                b.Reason += $" Rules {QuoteNames(maybeNames)} may narrow this further.";
            }
        }
        else if (vMax == Verdict.Blocked)
        {
            b.Verdict = Verdict.Blocked;
            if (blockNames.Count > 0)
            {
                b.Reason = $"Blocked on {iface.Alias}: the firewall rule {QuoteNames(blockNames)} blocks it.";
            }
            else if (state.DefaultInboundBlock)
            {
                b.Reason = $"Blocked on {iface.Alias}: no firewall rule allows it on {prof.Label()} networks, and the default is to block.";
            }
            else
            {
                b.Reason = $"Blocked on {iface.Alias} by the firewall.";
            }
            if (authOnly.Count > 0)
            {
                b.Reason += $" (Rule {QuoteNames(authOnly)} only allows IPsec-authenticated computers.)";
            }
        }
        else
        {
            b.Verdict = Verdict.Uncertain;
            b.Scope = sMax;
            b.Remote = effMax.Describe();
            var why = maybeWhy.Count > 0 ? string.Join("; ", maybeWhy.Values) : "conditions SimplySec could not evaluate";
            var hint = maybeWhy.Keys.Any(NeedsAdminWhy.Contains)
                ? " Running SimplySec as administrator usually resolves this."
                : "";
            b.Reason = $"Not sure for {iface.Alias}: the firewall rule {QuoteNames(maybeNames)} depends on {why}. " +
                       $"SimplySec does not guess, so this is not reported as protected.{hint}";
        }
        return b;
    }

    public static List<NetInterface> CandidateInterfaces(Listener lst, List<NetInterface> interfaces)
    {
        if (lst.IsLoopback)
        {
            return [];
        }
        var fam = lst.Family;
        if (lst.IsWildcard)
        {
            return interfaces.Where(i => i.Up && i.Kind != InterfaceKind.Loopback && i.IpInterfaces().Any(x => x.Family == fam)).ToList();
        }
        return interfaces.Where(i => i.HasIp(lst.Address) && i.Kind != InterfaceKind.Loopback).ToList();
    }

    /// <summary>Evaluate one listener. <paramref name="rules"/> can be pre-compiled for speed.</summary>
    public static Exposure Evaluate(Listener lst, FirewallState fw, EvalContext ctx, List<CompiledRule>? rules = null)
    {
        rules ??= CompileRules(fw.Rules, ctx.Env);
        if (lst.IsLoopback)
        {
            return new Exposure
            {
                Listener = lst,
                Verdict = Verdict.LocalOnly,
                Reason = $"Only programs on this PC can connect: it listens on {lst.Address} (loopback).",
            };
        }
        var cands = CandidateInterfaces(lst, ctx.Interfaces);
        if (cands.Count == 0)
        {
            if (lst.IsWildcard)
            {
                return new Exposure
                {
                    Listener = lst,
                    Verdict = Verdict.LocalOnly,
                    Reason = "No active network connection can reach it right now.",
                };
            }
            return new Exposure
            {
                Listener = lst,
                Verdict = Verdict.Uncertain,
                Reason = $"It listens on {lst.Address}, which SimplySec could not match to a network adapter.",
            };
        }
        var per = cands.Select(i => EvaluateOnInterface(lst, i, fw, rules, ctx)).ToList();
        if (!string.IsNullOrEmpty(lst.PackageSid))
        {
            foreach (var ie in per.Where(ie => ie.Verdict == Verdict.Reachable))
            {
                ie.Verdict = Verdict.Uncertain;
                ie.Reason += " This is a sandboxed Store app; Windows may still isolate it.";
            }
        }
        var reachable = per.Where(p => p.Verdict == Verdict.Reachable).ToList();
        if (reachable.Count > 0)
        {
            var scope = reachable[0].Scope;
            foreach (var p in reachable.Skip(1))
            {
                scope = EnumText.MaxRank(scope, p.Scope);
            }
            return new Exposure
            {
                Listener = lst, Verdict = Verdict.Reachable, Scope = scope, PerInterface = per,
                Reason = string.Join(" ", reachable.Select(p => p.Reason)),
            };
        }
        var uncertain = per.Where(p => p.Verdict == Verdict.Uncertain).ToList();
        if (uncertain.Count > 0)
        {
            return new Exposure
            {
                Listener = lst, Verdict = Verdict.Uncertain, Scope = Scope.None, PerInterface = per,
                Reason = string.Join(" ", uncertain.Select(p => p.Reason)),
            };
        }
        return new Exposure
        {
            Listener = lst, Verdict = Verdict.Blocked, Scope = Scope.None, PerInterface = per,
            Reason = string.Join(" ", per.Select(p => p.Reason)),
        };
    }

    public static List<Exposure> EvaluateAll(List<Listener> listeners, FirewallState fw, EvalContext ctx)
    {
        var rules = CompileRules(fw.Rules, ctx.Env);
        return listeners.Select(l => Evaluate(l, fw, ctx, rules)).ToList();
    }

    public static bool ProfileReachable(Exposure exposure, Profile profile) =>
        exposure.PerInterface.Any(ie => ie.Verdict == Verdict.Reachable && ie.Profile == profile);
}
