using SimplySec.Core.Checks;
using SimplySec.Core.Engine;
using SimplySec.Core.Eval;
using SimplySec.Core.Knowledge;
using SimplySec.Core.Model;
using SimplySec.Core.Tests.Support;

namespace SimplySec.Core.Tests;

/// <summary>Real cases from this PC (fixture captured read-only on 2026-11-02), ported from test_this_pc.py.</summary>
public class ThisPcTests
{
    private const string Ollama = @"C:\Users\micha\AppData\Local\Programs\Ollama\ollama.exe";
    private const string Micha = "S-1-5-21-828318626-1834032441-4028443802-1001";
    private const string CodexUser = "S-1-5-21-828318626-1834032441-4028443802-1004";

    static ThisPcTests() => Pinned.Apply();

    private static RawScan Raw() => RawScan.FromJson(Golden.Fixture("this_pc_raw.json"));

    private static EvalContext Ctx(RawScan raw) =>
        new(raw.Interfaces, raw.Env.ToDictionary(kv => kv.Key.ToUpperInvariant(), kv => kv.Value, StringComparer.Ordinal));

    private static Listener OllamaListener(string? user) => new()
    {
        Protocol = "tcp", Address = "0.0.0.0", Port = 11434, Pid = 1234, Process = "ollama.exe", Exe = Ollama, UserSid = user,
    };

    [Fact]
    public void OllamaReachableOnPrivateAndPublic()
    {
        var raw = Raw();
        var exp = Evaluator.Evaluate(OllamaListener(Micha), raw.Firewall, Ctx(raw));
        Assert.Equal(Verdict.Reachable, exp.Verdict);
        var reach = exp.Reachable.ToDictionary(ie => ie.Interface);
        Assert.Equal(Profile.Public, reach["Ethernet"].Profile);
        Assert.Contains("ollama.exe", reach["Ethernet"].AllowRules);
        Assert.Contains("Tailscale", reach.Keys);
    }

    [Fact]
    public void OllamaFindingIsUserConfiguredNotAThreat()
    {
        var raw = Raw();
        raw.Listeners.Add(OllamaListener(Micha));
        var result = Analysis.Analyze(raw);
        var f = result.Finding("exposure.program:ollama.exe")!;
        Assert.True(f.UserConfigured);
        Assert.Contains("you set this up", f.Title, StringComparison.Ordinal);
        Assert.True(f.Severity <= Severity.Low);
        Assert.Superset(new HashSet<string> { "exposure.block_program_public", "exposure.block_program" }, f.Fixes.Select(o => o.FixId).ToHashSet());
        Assert.NotNull(f.KeepKey);
        var row = result.Ports.First(p => p.Port == 11434);
        Assert.True(row.Verdict == Verdict.Reachable && row.Rules.Contains("ollama.exe"));
    }

    [Fact]
    public void OllamaRuleOnlyWhenNotRunning()
    {
        var f = Analysis.Analyze(Raw()).Finding("exposure.rule:ollama.exe")!;
        Assert.True(f.UserConfigured && f.Severity == Severity.Info);
    }

    [Fact]
    public void CodexRuleDoesNotCoverOtherUsers()
    {
        var raw = Raw();
        Assert.Contains(raw.Firewall.Rules, r => r.Name == "codex_sandbox_offline_block_inbound" && r.LocalUserAuthorized.Length > 0);
        Assert.Equal(Verdict.Reachable, Evaluator.Evaluate(OllamaListener(Micha), raw.Firewall, Ctx(raw)).Verdict);
        Assert.Equal(Verdict.Blocked, Evaluator.Evaluate(OllamaListener(CodexUser), raw.Firewall, Ctx(raw)).Verdict);
        Assert.Equal(Verdict.Uncertain, Evaluator.Evaluate(OllamaListener(null), raw.Firewall, Ctx(raw)).Verdict);
    }

    [Fact]
    public void CursorBoundToTailscaleOnly()
    {
        var result = Analysis.Analyze(Raw());
        var row = result.Ports.First(p => p.Port == 3000 && p.Process.Equals("cursor.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(Verdict.Reachable, row.Verdict);
        Assert.Equal("Tailscale network", row.ReachableFrom);
        var exp = result.Exposures.First(e => e.Listener.Port == 3000);
        Assert.Equal(["Tailscale"], exp.PerInterface.Select(ie => ie.Interface));
        Assert.Equal(Scoring.WidthVpn, result.Finding("exposure.program:cursor.exe")!.Width);
    }

    [Fact]
    public void SmbAndRpcBlockedOnPublicEthernet()
    {
        var result = Analysis.Analyze(Raw());
        foreach (var port in new[] { 135, 445, 5357 })
        {
            var eth = result.Exposures.Where(e => e.Listener.Port == port && e.Listener.Protocol == "tcp")
                .SelectMany(e => e.PerInterface).Where(ie => ie.Interface == "Ethernet").ToList();
            Assert.True(eth.Count > 0 && eth.All(ie => ie.Verdict == Verdict.Blocked), $"port {port}");
        }
    }

    [Fact]
    public void WholeScanIsSane()
    {
        var result = Analysis.Analyze(Raw());
        Assert.InRange(result.Score, 0, 100);
        Assert.Empty(result.Errors);
        Assert.StartsWith("Ethernet: Public network", result.NetworkStatus()[0], StringComparison.Ordinal);
        Assert.Equal(0, (int)result.Counts()["critical"]!);
        Assert.Equal(Scoring.WidthPublicAny, result.Finding("exposure.program:spotifylauncher.exe")!.Width);
        Assert.True(result.Finding("exposure.public_rules")!.Details.Count > 5);
        Assert.Equal(FindingStatus.Info, result.Finding("exposure.protected")!.Status);
    }

    [Fact]
    public void KnowledgeBaseIsValid()
    {
        var kb = KnowledgeBase.Load();
        Assert.Empty(kb.Errors);
        Assert.True(kb.Ports.Count > 60 && kb.Programs.Count > 0 && kb.Services.Count > 0);
        Assert.DoesNotContain(kb.AllFixIds(), id => !Registry.Fixes.ContainsKey(id));
        Assert.Contains("WSD", kb.Port("tcp", 5357)!.Name, StringComparison.Ordinal);
        Assert.Equal(Severity.High, kb.Port("tcp", 10000)!.Risk);
        Assert.Equal(Severity.Low, kb.Port("tcp", 2179)!.Risk);
        Assert.NotNull(kb.Port("tcp", 11434));
        Assert.Equal("ollama", kb.Program(@"C:\Users\x\AppData\Local\Programs\Ollama\ollama.exe")!.Id);
        Assert.Equal("cursor", kb.Program("CURSOR.EXE")!.Id);
        Assert.Null(kb.Program(""));
        Assert.Superset(new HashSet<string> { "rpcss", "mpssvc", "windefend", "dnscache", "bfe" }, kb.NeverTouch);
        var probes = kb.LanProbePorts().Select(p => p.Port).ToHashSet();
        Assert.Superset(new HashSet<int> { 23, 445, 554, 2375, 3389, 6379 }, probes);
        Assert.InRange(probes.Count, 26, 59);
    }

    [Fact]
    public void AllowListsRefuseTamperedActions()
    {
        var spec = ExposureCheck.FixBlockProgramPublic.Build!(new() { ["exe"] = @"C:\x\ollama.exe", ["label"] = "Ollama" })[0];
        var rule = spec.Params["rule"]!.AsObject();
        Assert.StartsWith("SimplySec:block_program_public:", (string)rule["name"]!, StringComparison.Ordinal);
        Assert.True(Registry.IsAllowed("firewall.add_rule", spec.Params));
        var allow = (System.Text.Json.Nodes.JsonObject)rule.DeepClone();
        allow["action"] = "allow";
        Assert.False(Registry.IsAllowed("firewall.add_rule", new() { ["rule"] = allow }));
        var renamed = (System.Text.Json.Nodes.JsonObject)rule.DeepClone();
        renamed["name"] = "Other";
        Assert.False(Registry.IsAllowed("firewall.add_rule", new() { ["rule"] = renamed }));
        Assert.False(Registry.IsAllowed("registry.value", new() { ["path"] = @"HKLM\SOFTWARE\Evil", ["name"] = "x", ["value"] = 1, ["type"] = "REG_DWORD" }));
        Assert.False(Registry.IsAllowed("netbios.adapter", new() { ["config_index"] = true, ["option"] = 2 }));
        Assert.True(Registry.IsAllowed("task.schedule", new() { ["name"] = Registry.DailyCheckTask, ["time"] = "07:30" }));
        Assert.False(Registry.IsAllowed("task.schedule", new() { ["name"] = Registry.DailyCheckTask, ["time"] = "24:00" }));
    }
}
