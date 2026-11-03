using System.Text.Json.Nodes;
using SimplySec.Core.Tests.Support;

namespace SimplySec.Windows.Tests;

/// <summary>
/// P6 gate, per fact: the native collector gives what facts.ps1 gives on this PC (read-only).
/// Error texts may differ; statuses and values may not.
/// </summary>
// Same collection as NativeTests: ScanStartsNoPowerShell watches every program started, so tests that
// run PowerShell must not run alongside it.
[Collection("os")]
public class NativeFactsTests(ITestOutputHelper output)
{
    private static string Script => Path.Combine(Golden.RepoRoot, "src", "simplysec", "windows", "scripts", "facts.ps1");

    [Fact]
    public async Task MatchesFactsPs1()
    {
        var reference = Task.Run(() => Runner.PowerShellFile(Script, timeout: 180) as JsonObject, TestContext.Current.CancellationToken);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var native = NativeFacts.Collect();
        output.WriteLine($"native facts: {sw.Elapsed.TotalSeconds:0.00} s");
        var ps = await reference ?? throw new InvalidOperationException("facts.ps1 returned nothing");

        var problems = new List<string>();
        foreach (var (name, expected) in ps)
        {
            if (name == "collected")
            {
                continue;
            }
            var actual = native[name];
            var es = expected?["status"]?.GetValue<string>();
            var a = actual?["status"]?.GetValue<string>();
            if (es != a)
            {
                problems.Add($"{name}: status {es} vs {a} ({actual?["error"]})");
                continue;
            }
            var ev = expected!["value"]?.DeepClone();
            var av = actual!["value"]?.DeepClone();
            if (name == "network")
            {
                // Only ever looked up by interface index; Get-NetIPConfiguration's own order isn't kept.
                ByIndex(ev);
                ByIndex(av);
            }
            if (es == "ok" && JsonAssert.FirstDiff(ev, av, name, []) is { } diff)
            {
                problems.Add(diff);
            }
        }
        foreach (var (name, _) in native)
        {
            if (!ps.ContainsKey(name))
            {
                problems.Add($"{name}: only in the native facts");
            }
        }
        foreach (var p in problems)
        {
            output.WriteLine(p);
        }
        Assert.Empty(problems);
    }

    [Fact]
    public async Task UsageMatchesTheOldScript()
    {
        var reference = await Task.Run(() => Runner.PowerShellJson(Usage.ReferenceScript, timeout: 60) as JsonObject, TestContext.Current.CancellationToken)
                        ?? throw new InvalidOperationException("usage script returned nothing");
        var native = Usage.Extra();
        // Get-LocalUser's LastLogon has sub-second precision; netapi32 gives whole seconds.
        foreach (var o in new[] { reference, native })
        {
            foreach (var row in (o["last_logons"] as JsonArray ?? []).OfType<JsonObject>())
            {
                if (row["last"]?.GetValue<string>() is { Length: >= 19 } t)
                {
                    row["last"] = t[..19];
                }
            }
        }
        Assert.Null(JsonAssert.FirstDiff(reference, native, "usage", []));
    }

    [Fact]
    public void ScanStartsNoPowerShell()
    {
        var started = new List<string>();
        void Record(string name)
        {
            lock (started)
            {
                started.Add(name);
            }
        }
        Runner.Started += Record;
        try
        {
            var raw = Collector.Collect();
            Assert.Empty(raw.Errors);
        }
        finally
        {
            Runner.Started -= Record;
        }
        output.WriteLine("started: " + string.Join(", ", started));
        Assert.DoesNotContain(started, n => n.Contains("powershell", StringComparison.OrdinalIgnoreCase) || n.Contains("pwsh", StringComparison.OrdinalIgnoreCase));
    }

    private static void ByIndex(JsonNode? network)
    {
        if (network?["ip"] is JsonArray ip)
        {
            var sorted = ip.Select(x => x!.DeepClone()).OrderBy(x => SimplySec.Core.Compat.Js.Long(x["index"])).ToArray();
            network["ip"] = new JsonArray(sorted);
        }
    }

    [Fact]
    public void HotfixTiesSortLikeWindowsPowerShell()
    {
        // Win32_QuickFixEngineering on this PC, and what Sort-Object InstalledOn -Descending gave.
        var oct = new DateTime(2026, 10, 14);
        var aug = new DateTime(2026, 8, 23);
        var items = new[] { (oct, "KB5127694"), (aug, "KB5054156"), (aug, "KB5095189"), (oct, "KB5121794"), (oct, "KB5127648"), (oct, "KB5127647") };
        NativeFacts.LegacyQuickSort(items, (a, b) => -a.Item1.CompareTo(b.Item1));
        Assert.Equal(["KB5121794", "KB5127648", "KB5127647", "KB5127694"], items.Take(4).Select(i => i.Item2));
    }

    [Fact]
    public void ListFactsUnwrapLikePowerShell()
    {
        Assert.Equal("{}", NativeFacts.PsUnwrap([]).ToJsonString());
        Assert.Equal("{\"a\":1}", NativeFacts.PsUnwrap([new JsonObject { ["a"] = 1 }]).ToJsonString());
        Assert.Equal("[1,2]", NativeFacts.PsUnwrap([JsonValue.Create(1), JsonValue.Create(2)]).ToJsonString());
    }
}
