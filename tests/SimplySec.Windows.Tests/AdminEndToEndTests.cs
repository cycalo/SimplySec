using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using SimplySec.Core.Engine;
using SimplySec.Core.Model;

namespace SimplySec.Windows.Tests;

/// <summary>
/// Port of tests/integration/test_admin_e2e.py. These change this PC and undo it, so they are
/// opt-in: run from an elevated prompt with SIMPLYSEC_ADMIN_TESTS=1, e.g.
///   $env:SIMPLYSEC_ADMIN_TESTS=1; dotnet test --project tests/SimplySec.Windows.Tests -- --filter-trait "Category=Admin"
/// </summary>
[Trait("Category", "Admin")]
[Collection("admin")]
public class AdminEndToEndTests
{
    private static void RequireOptIn()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("SIMPLYSEC_ADMIN_TESTS") == "1", "set SIMPLYSEC_ADMIN_TESTS=1 to run");
        Assert.SkipUnless(Elevation.IsAdmin(), "needs an elevated prompt");
    }

    private static PortRow Row(ScanResult result, int port) => result.Ports.First(p => p.Port == port && p.Protocol == "tcp");

    [Fact]
    public void FirewallFixAndUndo()
    {
        RequireOptIn();
        using var listener = new TcpListener(IPAddress.Any, 8765);
        listener.Start();
        var engine = WindowsHost.CreateEngine();
        var firewall = new Firewall();
        Assert.Empty(firewall.GroupRules());

        var before = engine.Scan(save: false);
        var row = Row(before, 8765);
        Assert.Equal(Environment.ProcessPath, row.Exe, StringComparer.OrdinalIgnoreCase);

        var plan = engine.Plan([new Selection("exposure.block_program", new JsonObject { ["exe"] = row.Exe, ["label"] = "SimplySec test listener" }, row.FindingId)]);
        var result = engine.Apply(plan);
        try
        {
            Assert.True(result.Ok, string.Join("; ", result.Outcomes.Select(o => $"{o.Status} {o.Error}")));
            Assert.False(string.IsNullOrEmpty(result.Backup));

            var after = engine.Scan(save: false);
            Assert.Contains(Row(after, 8765).Verdict, new[] { Verdict.Blocked, Verdict.LocalOnly });
            var group = firewall.GroupRules();
            var rule = Assert.Single(group);
            Assert.StartsWith("SimplySec:block_program:", rule.Name, StringComparison.Ordinal);
            Assert.Contains("Added by SimplySec", rule.Description, StringComparison.Ordinal);
        }
        finally
        {
            var outcomes = engine.Undo(everything: true);
            Assert.NotEmpty(outcomes);
            Assert.All(outcomes, o => Assert.True(o.Ok, o.Error));
            Assert.Empty(firewall.GroupRules());
        }
    }

    [Fact]
    public void RegistryFixAndUndo()
    {
        RequireOptIn();
        const string path = @"HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance";
        var registry = new RegistryAdapter();
        var original = registry.Read(path, "fAllowToGetHelp");
        var engine = WindowsHost.CreateEngine();
        engine.Scan(save: false);

        var result = engine.Apply(engine.Plan([new Selection("rdp.remote_assistance_off", new JsonObject())]));
        Assert.True(result.Ok);
        var now = registry.Read(path, "fAllowToGetHelp");
        Assert.True(now.Exists);
        Assert.Equal(0, SimplySec.Core.Compat.Js.Long(now.Value));

        Assert.All(engine.Undo(batchId: result.BatchId), o => Assert.True(o.Ok, o.Error));
        var restored = registry.Read(path, "fAllowToGetHelp");
        Assert.Equal(original.Exists, restored.Exists);
        Assert.Equal(original.Value?.ToJsonString(), restored.Value?.ToJsonString());
    }
}
