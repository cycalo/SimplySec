using SimplySec.Core.Compat;
using SimplySec.Core.Engine;
using SimplySec.Core.Model;
using SimplySec.Core.Storage;
using SimplySec.Core.Tests.Support;

namespace SimplySec.Core.Tests;

/// <summary>C# reads the journal and history Python v2 wrote, and undoes Python's changes.</summary>
public class CompatibilityTests
{
    private const string Ra = @"HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance";

    static CompatibilityTests() => Pinned.Apply();

    private static string Src(string name) => Path.Combine(Golden.RepoRoot, "tests", "golden", "compat", name);

    [Fact]
    public void ReadsPythonHistory()
    {
        using var tmp = new TempDir();
        File.Copy(Src("history.db"), tmp.File("history.db"));
        var h = new History(tmp.File("history.db"));
        var expected = Golden.Load("compat/expected");
        var scans = h.Scans();
        Assert.Single(scans);
        JsonAssert.Equal(expected["scan"], h.ScanData(scans[0].Id), "stored scan");
        var parsed = ScanResult.FromJson(h.ScanData(scans[0].Id)!);
        Assert.Equal(Js.Int(expected["scan"]!["score"]), parsed.Score);
        Assert.Equal(5, h.AcceptedWidths()["keep:exposure.program:spotifylauncher.exe"]);
        Assert.Equal("07:30", Js.Str(h.GetSetting("daily_check")!["time"]));
        var dev = h.Devices().Single();
        Assert.Equal("OLED", Js.Str(dev["data"]!["model"]));
        Assert.True(Js.PyEquals(h.GetSetting("score_scale"), System.Text.Json.Nodes.JsonValue.Create("risk")));
    }

    [Fact]
    public void UndoesPythonChanges()
    {
        using var tmp = new TempDir();
        Directory.CreateDirectory(tmp.File("data"));
        File.Copy(Src("journal.db"), tmp.File("data/simplysec.db"));
        var (engine, a) = TestEngines.Make(tmp);
        var reg = (FakeRegistry)a.Registry;
        var fw = (FakeFirewall)a.Firewall;
        var sys = (FakeSystem)a.System;
        // The state Python left behind.
        reg.Values[(Ra, "fAllowToGetHelp")] = ("REG_DWORD", 0);
        foreach (var r in Golden.Load("compat/expected")["fw_rules"]!.AsArray())
        {
            fw.Rules.Add(FirewallRule.FromJson(r!));
        }
        sys.Smb1 = false;

        var changes = engine.Journal.Changes();
        Assert.Equal(["registry.value", "firewall.add_rule", "smb.server_setting"], changes.Select(c => c.Kind));
        Assert.All(changes, c => Assert.True(c.Status == "applied" && c.Verified == true));

        var undone = engine.Undo(everything: true);
        Assert.All(undone, u => Assert.True(u.Ok, u.Error));
        Assert.Equal(1, Js.Int(reg.Values[(Ra, "fAllowToGetHelp")].Value));
        Assert.Empty(fw.Rules);
        Assert.True(sys.Smb1);

        // C# can keep writing to the same journal.
        var batch = engine.Journal.BeginBatch("C# batch", ["x"]);
        Assert.True(batch > 1);
    }
}
