using System.Text.Json.Nodes;
using SimplySec.Core.Tests.Support;

namespace SimplySec.Windows.Tests;

/// <summary>Native facts on this PC (read-only): no PowerShell, and PowerShell's list and sort rules.</summary>
public class NativeFactsTests(ITestOutputHelper output)
{
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
