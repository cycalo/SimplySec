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
        DailyTarget = () => (ThisCopy, "monitor --run"),
    });

    private const string ThisCopy = "C:/Apps/SimplySec/SimplySec.exe";

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

    private static string TaskXml(string command, string time) =>
        "<Task xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'><Triggers><CalendarTrigger><StartBoundary>2026-11-01T"
        + time + ":00</StartBoundary></CalendarTrigger></Triggers><Actions><Exec><Command>" + command
        + "</Command><Arguments>monitor --run</Arguments></Exec></Actions></Task>";

    [Fact]
    public void ElevateAddsYesOnlyWhereAccepted()
    {
        var engine = TestEngines.Make(_tmp, false, Raw()).Engine;
        var seen = new List<string[]>();
        CliHost Host() => new()
        {
            Engine = () => engine,
            IsAdmin = () => false,
            ReadLine = () => null,
            Out = _out,
            Err = _err,
            JournalPath = () => _tmp.File("data/simplysec.db"),
            RunElevated = a => { seen.Add([.. a]); return (Elevation.ElevatedStatus.Finished, 0); },
        };
        Assert.Equal(Cli.ExitOk, new Cli(Host()).Run(["monitor", "--enable", "07:05", "--elevate"]));
        Assert.Equal(Cli.ExitOk, new Cli(Host()).Run(["undo", "--all", "--elevate"]));
        Assert.Equal(["monitor", "--enable", "07:05"], seen[0]);
        Assert.Equal(["undo", "--all", "--yes"], seen[1]);
    }

    [Fact]
    public void MonitorStatusPointsOutAnOlderCopy()
    {
        var (engine, adapters) = TestEngines.Make(_tmp, admin: false, Raw());
        var tasks = ((FakeScheduler)adapters.Scheduler!).Tasks;
        var cli = MakeCli(engine, admin: false);
        Assert.Equal(Cli.ExitOk, cli.Run(["monitor", "--status"]));
        Assert.Equal("Daily check: off.", _out.ToString().Trim());

        tasks[DailyCheck.TaskName] = TaskXml("C:/Old/SimplySec/SimplySec.exe", "07:05");
        _out.GetStringBuilder().Clear();
        Assert.Equal(Cli.ExitOk, cli.Run(["monitor", "--status"]));
        var text = _out.ToString();
        Assert.Contains("Daily check: on, daily at 07:05.", text, StringComparison.Ordinal);
        Assert.Contains("simplysec-cli monitor --enable 07:05 --elevate", text, StringComparison.Ordinal);

        tasks[DailyCheck.TaskName] = TaskXml(ThisCopy, "07:05");
        _out.GetStringBuilder().Clear();
        cli.Run(["monitor", "--status"]);
        Assert.DoesNotContain("--enable", _out.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void PrivateNetworkNeedsAnInterfaceIndex()
    {
        Assert.Equal(Cli.ExitUsage, FakeCli(admin: true).Run(["fix", "--finding", "a", "--fix", "b", "--private-network", "home"]));
        Assert.Contains("argument --private-network: invalid int value: 'home'", _err.ToString(), StringComparison.Ordinal);
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
