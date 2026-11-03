using System.Text.Json.Nodes;
using SimplySec.Commands;
using SimplySec.Core.Compat;
using SimplySec.Core.Engine;
using SimplySec.Core.Tests.Support;

namespace SimplySec.Windows.Tests;

/// <summary>Port of tests/unit/test_cli.py: CLI output shape on the real-data fixture, no OS access.</summary>
public sealed class CliTests : IDisposable
{
    private readonly TempDir _tmp = new();
    private readonly StringWriter _out = new();
    private readonly StringWriter _err = new();

    public void Dispose()
    {
        _tmp.Dispose();
        _out.Dispose();
        _err.Dispose();
    }

    private static RawScan Raw() => RawScan.FromJson(Golden.Fixture("this_pc_raw.json"));

    private Cli MakeCli(ScanEngine engine, bool admin) => new(new CliHost
    {
        Engine = () => engine,
        IsAdmin = () => admin,
        ReadLine = () => null,
        Out = _out,
        Err = _err,
        JournalPath = () => _tmp.File("data/simplysec.db"),
        Notify = (_, _) => true,
        Lan = () => throw new InvalidOperationException("no network in tests"),
        RunElevated = _ => throw new InvalidOperationException("no elevation in tests"),
    });

    private Cli FakeCli(bool admin = false) => MakeCli(TestEngines.Make(_tmp, admin, Raw()).Engine, admin);

    private static void HasKeys(JsonNode? node, params string[] keys)
    {
        var obj = Assert.IsType<JsonObject>(node);
        foreach (var k in keys)
        {
            Assert.True(obj.ContainsKey(k), $"missing key '{k}'");
        }
    }

    [Fact]
    public void ScanJsonShape()
    {
        Assert.Equal(Cli.ExitOk, FakeCli().Run(["scan", "--json", "--no-save"]));
        var data = JsonNode.Parse(_out.ToString())!.AsObject();
        HasKeys(data, "version", "score", "grade", "counts", "network", "findings", "ports", "exposures", "firewall", "interfaces", "errors");
        Assert.False(data.ContainsKey("facts"));
        HasKeys(data["findings"]![0], "id", "check", "area", "title", "severity", "what_it_means", "details", "fixes", "status");
        HasKeys(data["ports"]![0], "protocol", "port", "process", "listening_on", "reachable_from", "verdict", "risk", "rules");
        Assert.Equal(["critical", "high", "low", "medium"], data["counts"]!.AsObject().Select(kv => kv.Key).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void ScanText()
    {
        Assert.Equal(Cli.ExitOk, FakeCli().Run(["scan", "--no-save"]));
        var output = _out.ToString();
        Assert.Contains("Risk score", output, StringComparison.Ordinal);
        Assert.Contains("Ports other devices can reach", output, StringComparison.Ordinal);
    }

    [Fact]
    public void FixNeedsAdmin() => Assert.Equal(Cli.ExitNeedsAdmin, FakeCli(admin: false).Run(["fix", "recommended", "--yes"]));

    [Fact]
    public void ChangesEmpty()
    {
        Assert.Equal(Cli.ExitOk, FakeCli().Run(["changes"]));
        Assert.Contains("has not changed anything", _out.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void UnknownCommandListsChoices()
    {
        Assert.Equal(Cli.ExitUsage, FakeCli().Run(["bogus"]));
        Assert.Contains(
            "argument command: invalid choice: 'bogus' (choose from 'scan', 'fix', 'keep', 'undo', 'changes', 'history', 'monitor', 'report')",
            _err.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void FixFlowEndToEndWithFakes()
    {
        var (engine, adapters) = TestEngines.Make(_tmp, admin: true, Raw());
        var registry = (FakeRegistry)adapters.Registry;
        const string path = @"HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance";
        registry.Values[(path, "fAllowToGetHelp")] = ("REG_DWORD", 1);

        var code = MakeCli(engine, admin: true).Run(["fix", "--finding", "rdp.remote_assistance_on", "--fix", "rdp.remote_assistance_off", "--yes"]);

        var output = _out.ToString();
        Assert.Contains("SimplySec will make these changes", output, StringComparison.Ordinal);
        Assert.Contains("What might stop working", output, StringComparison.Ordinal);
        Assert.Contains("Verified ✓", output, StringComparison.Ordinal);
        // The fixture doesn't change, so the fresh scan honestly still reports the finding.
        Assert.Contains("STILL PRESENT", output, StringComparison.Ordinal);
        Assert.Equal(Cli.ExitFail, code);
        var (type, value) = registry.Values[(path, "fAllowToGetHelp")];
        Assert.Equal("REG_DWORD", type);
        Assert.Equal(0, Js.Long(value));
    }
}
