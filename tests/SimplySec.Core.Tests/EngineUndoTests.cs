using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using SimplySec.Core.Compat;
using SimplySec.Core.Engine;
using SimplySec.Core.Model;
using SimplySec.Core.Storage;
using SimplySec.Core.Tests.Support;

namespace SimplySec.Core.Tests;

/// <summary>Apply, verify and undo with fake OS adapters.</summary>
public class EngineUndoTests
{
    private const string Ra = @"HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance";

    static EngineUndoTests() => Pinned.Apply();

    private static Plan Plan(params Selection[] sels) => Analysis.BuildPlan([.. sels]);

    private static void Sql(string path, string sql, params object[] args)
    {
        using var db = new SqliteConnection($"Data Source={path};Pooling=False");
        db.Open();
        using var cmd = db.CreateCommand();
        cmd.CommandText = sql;
        for (var i = 0; i < args.Length; i++)
        {
            cmd.Parameters.AddWithValue($"$p{i}", args[i]);
        }
        cmd.ExecuteNonQuery();
    }

    [Fact]
    public void ApplyVerifyAndUndoInReverseOrder()
    {
        using var tmp = new TempDir();
        var (engine, a) = TestEngines.Make(tmp);
        var reg = (FakeRegistry)a.Registry;
        var fw = (FakeFirewall)a.Firewall;
        var sys = (FakeSystem)a.System;
        reg.Values[(Ra, "fAllowToGetHelp")] = ("REG_DWORD", 1);
        var plan = Plan(
            new Selection("rdp.remote_assistance_off", [], "rdp.remote_assistance_on"),
            new Selection("exposure.block_program", new JsonObject { ["exe"] = @"C:\t\a.exe", ["label"] = "A" }, "x"),
            new Selection("legacy.smb1_off", [], "legacy.smb1_on"));
        var res = engine.Apply(plan, restorePoint: true);
        Assert.Equal(["applied", "applied", "applied"], res.Outcomes.Select(o => o.Status));
        Assert.All(res.Outcomes, o => Assert.True(o.Verified));
        Assert.True(res.Backup is not null && fw.Exports == 1);
        Assert.Contains(res.Warnings, w => w.Contains("Restore point", StringComparison.Ordinal));
        Assert.Equal(0, Js.Int(reg.Values[(Ra, "fAllowToGetHelp")].Value));
        Assert.False(sys.Smb1);
        Assert.Single(fw.GroupRules());

        var undone = engine.Undo(everything: true);
        Assert.Equal(["smb.server_setting", "firewall.add_rule", "registry.value"], undone.Select(u => u.Change.Kind));
        Assert.All(undone, u => Assert.True(u.Ok));
        Assert.Equal(1, Js.Int(reg.Values[(Ra, "fAllowToGetHelp")].Value));
        Assert.True(sys.Smb1);
        Assert.Empty(fw.Rules);
        Assert.All(engine.Journal.Changes(), c => Assert.Equal("reverted", c.Status));
    }

    [Fact]
    public void ValueWeCreatedIsDeletedOnUndo()
    {
        using var tmp = new TempDir();
        var (engine, a) = TestEngines.Make(tmp);
        var reg = (FakeRegistry)a.Registry;
        engine.Apply(Plan(new Selection("legacy.llmnr_off", [], "legacy.llmnr_on")));
        var key = (@"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast");
        Assert.Equal(0, Js.Int(reg.Values[key].Value));
        engine.Undo(batchId: 1);
        Assert.False(reg.Values.ContainsKey(key));
    }

    [Fact]
    public void FailedApplyIsRecordedAndOthersContinue()
    {
        using var tmp = new TempDir();
        var (engine, a) = TestEngines.Make(tmp);
        ((FakeRegistry)a.Registry).FailOn = "fAllowToGetHelp";
        var res = engine.Apply(Plan(new Selection("rdp.remote_assistance_off", [], "f1"), new Selection("legacy.smb1_off", [], "f2")));
        Assert.Equal(["failed", "applied"], res.Outcomes.Select(o => o.Status));
        Assert.Contains("access denied", res.Outcomes[0].Error, StringComparison.Ordinal);
        Assert.False(res.Ok);
        Assert.Equal(["failed", "applied"], engine.Journal.Changes().Select(c => c.Status));
    }

    [Fact]
    public void NeedsAdmin()
    {
        using var tmp = new TempDir();
        var (engine, _) = TestEngines.Make(tmp, admin: false);
        Assert.Throws<NeedsAdminException>(() => engine.Apply(Plan(new Selection("legacy.smb1_off"))));
        Assert.Throws<NeedsAdminException>(() => engine.Undo(everything: true));
    }

    [Fact]
    public void TamperedJournalIsRefused()
    {
        using var tmp = new TempDir();
        var (engine, a) = TestEngines.Make(tmp);
        engine.Apply(Plan(new Selection("legacy.smb1_off")));
        var evil = new JsonObject { ["path"] = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", ["name"] = "x", ["value"] = "evil.exe", ["type"] = "REG_SZ" };
        Sql(tmp.File("data/simplysec.db"), "UPDATE changes SET kind='registry.value', params=$p0", evil.ToJsonString());
        var output = engine.Undo(everything: true);
        Assert.False(output[0].Ok);
        Assert.Contains("allow-list", output[0].Error, StringComparison.Ordinal);
        Assert.False(((FakeRegistry)a.Registry).Values.ContainsKey((@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "x")));
    }

    [Fact]
    public void TamperedBeforeStateIsRefused()
    {
        using var tmp = new TempDir();
        var (engine, a) = TestEngines.Make(tmp);
        var fw = (FakeFirewall)a.Firewall;
        fw.Rules.Add(new FirewallRule { Name = "BlockPort139-TCP-in", Action = "block" });
        engine.Apply(Plan(new Selection("housekeeping.remove_v1_rules", new JsonObject { ["names"] = new JsonArray("BlockPort139-TCP-in") })));
        var before = new JsonObject { ["rules"] = new JsonArray(new FirewallRule { Name = "Allow everything", Action = "allow" }.ToJson()) };
        Sql(tmp.File("data/simplysec.db"), "UPDATE changes SET before=$p0", before.ToJsonString());
        var output = engine.Undo(everything: true);
        Assert.False(output[0].Ok);
        Assert.Empty(fw.FindRules("Allow everything"));
    }

    [Fact]
    public void RemoveRuleUndoRecreatesDefinition()
    {
        using var tmp = new TempDir();
        var (engine, a) = TestEngines.Make(tmp);
        var fw = (FakeFirewall)a.Firewall;
        var original = new FirewallRule { Name = "SimpleSec-WinRM-5985-AllowLocal", Action = "allow", Protocol = 6, LocalPorts = "5985", RemoteAddresses = "LocalSubnet" };
        fw.Rules.Add(original);
        engine.Apply(Plan(new Selection("housekeeping.remove_v1_rules", new JsonObject { ["names"] = new JsonArray(original.Name) })));
        Assert.Empty(fw.Rules);
        engine.Undo(everything: true);
        Assert.Single(fw.Rules);
        JsonAssert.Equal(original.ToJson(), fw.Rules[0].ToJson(), "recreated rule");
    }

    [Fact]
    public void RemoveAllRulesAlsoClearsUnjournaledGroupRules()
    {
        using var tmp = new TempDir();
        var (engine, a) = TestEngines.Make(tmp);
        var fw = (FakeFirewall)a.Firewall;
        engine.Apply(Plan(new Selection("exposure.block_program", new JsonObject { ["exe"] = @"C:\a.exe" })));
        fw.Rules.Add(new FirewallRule { Name = "SimplySec:orphan:1", Action = "block", Grouping = "SimplySec" });
        var (outcomes, leftovers) = engine.RemoveAllRules();
        Assert.True(outcomes.Count == 1 && outcomes[0].Ok);
        Assert.Equal(["SimplySec:orphan:1"], leftovers);
        Assert.Empty(fw.GroupRules());
    }

    [Fact]
    public void FirewallProfileRoundTrip()
    {
        using var tmp = new TempDir();
        var (engine, a) = TestEngines.Make(tmp);
        var fw = (FakeFirewall)a.Firewall;
        fw.Profiles[Profile.Public].Enabled = false;
        engine.Apply(Plan(new Selection("firewall.enable", new JsonObject { ["profile"] = 4 })));
        Assert.True(fw.Profiles[Profile.Public].Enabled);
        engine.Undo(everything: true);
        Assert.False(fw.Profiles[Profile.Public].Enabled);
    }

    [Fact]
    public void ReadOnlyJournalRefusesWrites()
    {
        using var tmp = new TempDir();
        _ = new Journal(tmp.File("j.db"));
        var ro = new Journal(tmp.File("j.db"), readOnly: true);
        Assert.Throws<UnauthorizedAccessException>(() => ro.BeginBatch("x", []));
        Assert.Empty(ro.Changes());
    }
}
