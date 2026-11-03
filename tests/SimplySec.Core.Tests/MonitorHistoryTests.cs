using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using SimplySec.Core.Checks;
using SimplySec.Core.Compat;
using SimplySec.Core.Engine;
using SimplySec.Core.Knowledge;
using SimplySec.Core.Model;
using SimplySec.Core.Storage;
using SimplySec.Core.Tests.Support;

namespace SimplySec.Core.Tests;

/// <summary>Ports of test_monitor.py and the history/scoring parts of test_core_small.py.</summary>
public class MonitorHistoryTests
{
    static MonitorHistoryTests() => Pinned.Apply();

    private static JsonObject ScanD(int score, JsonObject[]? findings = null, JsonObject[]? devices = null) => new()
    {
        ["score"] = score,
        ["findings"] = new JsonArray((findings ?? []).Select(f => (JsonNode)f).ToArray()),
        ["ports"] = new JsonArray(),
        ["extras"] = new JsonObject { ["devices"] = new JsonArray((devices ?? []).Select(d => (JsonNode)d).ToArray()) },
    };

    private static JsonObject F(string id, string sev = "medium", string? title = null) =>
        new() { ["id"] = id, ["severity"] = sev, ["status"] = "open", ["title"] = title ?? id };

    [Fact]
    public void Triggers()
    {
        var s = ScanD(80, [F("a")]);
        Assert.Empty(DailyCheck.Triggers(s, s));
        Assert.Empty(DailyCheck.Triggers(ScanD(20), ScanD(24)));
        Assert.Empty(DailyCheck.Triggers(ScanD(20), ScanD(10)));
        Assert.Contains("rose from 20 to 25", DailyCheck.Triggers(ScanD(20), ScanD(25))[0], StringComparison.Ordinal);
        Assert.Equal(["New: Telnet is open."],
            DailyCheck.Triggers(ScanD(80, [F("a", "high")]), ScanD(80, [F("a", "high"), F("b"), F("c", "critical", "Telnet is open")])));
        Assert.Equal(["The firewall is off for Public networks."],
            DailyCheck.Triggers(ScanD(90), ScanD(90, [F("firewall.off.public", "critical", "The firewall is off for Public networks")])));
        Assert.Equal(["No antivirus is actively protecting this PC."],
            DailyCheck.Triggers(null, ScanD(90, [F("malware.no_antivirus", "critical", "No antivirus is actively protecting this PC")])));
        Assert.Equal(["New device on your network: Unknown camera."],
            DailyCheck.Triggers(ScanD(90, devices: [new JsonObject { ["mac"] = "AA" }]),
                ScanD(90, devices: [new JsonObject { ["mac"] = "AA" }, new JsonObject { ["mac"] = "BB", ["name"] = "Unknown camera" }])));
    }

    /// <summary>A daily-check task as v2's frozen build created it (trimmed to what is read).</summary>
    private const string V2TaskXml = """
        <?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <RegistrationInfo><Author>SimplySec</Author></RegistrationInfo>
          <Triggers><CalendarTrigger><StartBoundary>2026-10-01T18:30:00</StartBoundary></CalendarTrigger></Triggers>
          <Actions Context="Author"><Exec><Command>C:\Users\Tester\Downloads\SimplySec\SimplySec.exe</Command><Arguments>monitor --run</Arguments></Exec></Actions>
        </Task>
        """;

    [Fact]
    public void ReadsTheTaskAndSpotsAnotherCopy()
    {
        var task = DailyCheck.ParseTask("\uFEFF" + V2TaskXml + "\r\n")!;
        Assert.Equal(@"C:\Users\Tester\Downloads\SimplySec\SimplySec.exe", task.Command);
        Assert.Equal("monitor --run", task.Arguments);
        Assert.Equal("18:30", task.Time);
        Assert.True(DailyCheck.PointsElsewhere(task, @"D:\Apps\SimplySec-3.0.0-win64\SimplySec.exe", "monitor --run"));
        Assert.False(DailyCheck.PointsElsewhere(task, @"c:\users\tester\downloads\simplysec\SIMPLYSEC.EXE", "monitor --run"));
        Assert.False(DailyCheck.PointsElsewhere(task with { Command = "\"" + task.Command + "\"" }, task.Command, "monitor --run"));
        // v2 run from source: pythonw.exe -m simplysec monitor --run
        Assert.True(DailyCheck.PointsElsewhere(task with { Arguments = "-m simplysec monitor --run" }, task.Command, "monitor --run"));
        Assert.Null(DailyCheck.ParseTask(null));
        Assert.Null(DailyCheck.ParseTask("<Task>SimplySec 12:00</Task>"));
        Assert.Null(DailyCheck.ParseTask("not xml"));
    }

    [Fact]
    public void RepointingAV2TaskIsJournaledAndUndoable()
    {
        using var tmp = new TempDir();
        var (engine, a) = TestEngines.Make(tmp);
        var sched = (FakeScheduler)a.Scheduler!;
        sched.Tasks[DailyCheck.TaskName] = V2TaskXml;
        Assert.Equal("18:30", DailyCheck.CurrentTask(engine)!.Time);
        Assert.True(DailyCheck.Enable(engine, "18:30").Ok);
        Assert.EndsWith("18:30</Task>", sched.Tasks[DailyCheck.TaskName], StringComparison.Ordinal);
        Assert.True(engine.Undo(changeIds: [DailyCheck.ActiveChange(engine)!.Id]).All(o => o.Ok));
        Assert.Equal(V2TaskXml, sched.Tasks[DailyCheck.TaskName]);
    }

    [Fact]
    public void EnableMoveAndDisableAreJournaled()
    {
        using var tmp = new TempDir();
        var (engine, a) = TestEngines.Make(tmp);
        var sched = (FakeScheduler)a.Scheduler!;
        Assert.True(DailyCheck.Enable(engine, "12:00").Ok);
        Assert.EndsWith("12:00</Task>", sched.Tasks[DailyCheck.TaskName], StringComparison.Ordinal);
        Assert.True(DailyCheck.Enable(engine, "08:15").Ok);
        Assert.EndsWith("08:15</Task>", sched.Tasks[DailyCheck.TaskName], StringComparison.Ordinal);
        Assert.Equal([("task.schedule", "reverted"), ("task.schedule", "applied")], engine.Journal.Changes().Select(c => (c.Kind, c.Status)));
        Assert.True(DailyCheck.Disable(engine));
        Assert.False(sched.Tasks.ContainsKey(DailyCheck.TaskName));
        Assert.False(Js.Truthy(engine.History.GetSetting(DailyCheck.Setting)!["enabled"]));
    }

    [Fact]
    public void MonitorRunSavesAndNotifies()
    {
        using var tmp = new TempDir();
        var raw = RawScan.FromJson(Golden.Fixture("this_pc_raw.json"));
        var (engine, _) = TestEngines.Make(tmp, raw: raw);
        var shown = new List<(string, List<string>)>();
        Assert.Equal(0, DailyCheck.RunOnce(engine, null, (t, l) => shown.Add((t, l))));
        Assert.Equal("monitor", engine.History.Scans()[0].Kind);
        Assert.Empty(shown);
        var data = Analysis.Analyze(raw).ToJson(includeFacts: false);
        data["score"] = 0;
        using (var db = new SqliteConnection($"Data Source={engine.History.Path};Pooling=False"))
        {
            db.Open();
            using var cmd = db.CreateCommand();
            cmd.CommandText = "UPDATE scans SET data=$d, score=0";
            cmd.Parameters.AddWithValue("$d", data.ToJsonString());
            cmd.ExecuteNonQuery();
        }
        DailyCheck.RunOnce(engine, null, (t, l) => shown.Add((t, l)));
        Assert.NotEmpty(shown);
        Assert.Contains("rose from 0", shown[0].Item2[0], StringComparison.Ordinal);
    }

    private static Finding Fd(Severity sev, FindingStatus status = FindingStatus.Open) =>
        new() { Id = "x", Check = "c", Area = "a", Title = "t", Severity = sev, WhatItMeans = "w", Status = status };

    [Fact]
    public void ScoreAndGrade()
    {
        Assert.Equal(0, Scoring.Score([]));
        Assert.Equal(25 + 12 + 5 + 2, Scoring.Score([Fd(Severity.Critical), Fd(Severity.High), Fd(Severity.Medium), Fd(Severity.Low)]));
        Assert.Equal(0, Scoring.Score([Fd(Severity.High, FindingStatus.Accepted), Fd(Severity.Info)]));
        Assert.Equal(100, Scoring.Score(Enumerable.Repeat(Fd(Severity.Critical), 5)));
        Assert.Equal(["A", "B", "C", "D", "E", "F"], new[] { 5, 15, 25, 45, 65, 90 }.Select(v => Scoring.Grade(v)));
        Assert.Equal(["A", "B", "C", "C", "D"], new[] { 9, 10, 31, 34, 35 }.Select(v => Scoring.Grade(v)));
        Assert.Equal("D", Scoring.Grade(25, [Fd(Severity.Critical)]));
        Assert.Equal("C", Scoring.Grade(12, [Fd(Severity.High)]));
        Assert.Equal("E", Scoring.Grade(60, [Fd(Severity.High)]));
        Assert.Equal("B", Scoring.Grade(12, [Fd(Severity.High, FindingStatus.Accepted)]));
    }

    [Fact]
    public void ScoringGoldens()
    {
        foreach (var c in Golden.Load("primitives")["exposure_severity"]!.AsArray())
        {
            var result = Scoring.ExposureSeverity(EnumText.ParseSeverity(Js.Str(c!["base"])), Js.Int(c["width"]),
                Js.Bool(c["unsigned"]), Js.Bool(c["user_writable"]), Js.Bool(c["user_configured"]));
            Assert.True(Js.Str(c["result"]) == result.Key(), c.ToJsonString());
        }
        foreach (var c in Golden.Load("primitives")["grades"]!.AsArray())
        {
            var findings = c!["findings"]!.AsArray().Select(f => new Finding
            {
                Id = "f", Check = "c", Area = "a", Title = "t", WhatItMeans = "",
                Severity = EnumText.ParseSeverity(Js.Str(f!["severity"])),
                Status = EnumText.ParseStatus(Js.Str(f["status"])),
            }).ToList();
            if (findings.Count > 0)
            {
                Assert.Equal(Js.Int(c["score"]), Scoring.Score(findings));
            }
            Assert.True(Js.Str(c["grade"]) == Scoring.Grade(Js.Int(c["score"]), findings), c.ToJsonString());
        }
    }

    [Fact]
    public void OldScansAreConvertedToRiskScale()
    {
        using var tmp = new TempDir();
        var path = tmp.File("old.db");
        using (var db = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            db.Open();
            using var cmd = db.CreateCommand();
            cmd.CommandText = "CREATE TABLE scans(id INTEGER PRIMARY KEY, ts TEXT NOT NULL, kind TEXT NOT NULL, score INTEGER NOT NULL, grade TEXT NOT NULL, data TEXT NOT NULL);" +
                              "INSERT INTO scans(ts, kind, score, grade, data) VALUES ('t', 'manual', 60, 'D', '{\"score\": 60, \"grade\": \"D\"}')";
            cmd.ExecuteNonQuery();
        }
        var h = new History(path);
        Assert.Equal((40, "D"), (h.Scans()[0].Score, h.Scans()[0].Grade));
        Assert.Equal(40, Js.Int(h.Latest(1)[0]["score"]));
        _ = new History(path);
        Assert.Equal(40, h.Scans()[0].Score);
    }

    [Fact]
    public void IntentAndPaths()
    {
        var ollama = KnowledgeBase.Load().ProgramById("ollama");
        Assert.True(ExposureCheck.UserConfigured(ollama, new Dictionary<string, string> { ["OLLAMA_HOST"] = "0.0.0.0:11434" }));
        Assert.True(ExposureCheck.UserConfigured(ollama, new Dictionary<string, string> { ["OLLAMA_HOST"] = "[::]:11434" }));
        Assert.False(ExposureCheck.UserConfigured(ollama, new Dictionary<string, string> { ["OLLAMA_HOST"] = "127.0.0.1:11434" }));
        Assert.False(ExposureCheck.UserConfigured(ollama, new Dictionary<string, string>()));
        var env = new Dictionary<string, string> { ["LOCALAPPDATA"] = @"C:\Users\a\AppData\Local" };
        Assert.True(ExposureCheck.IsUserWritable(@"C:\Users\a\AppData\Local\Programs\x.exe", env));
        Assert.False(ExposureCheck.IsUserWritable(@"C:\Program Files\x.exe", env));
    }

    [Fact]
    public void ScanResultRoundTripAndHistoryCompare()
    {
        using var tmp = new TempDir();
        var raw = RawScan.FromJson(Golden.Fixture("this_pc_raw.json"));
        var r1 = Analysis.Analyze(raw);
        var again = ScanResult.FromJson(r1.ToJson());
        JsonAssert.Equal(r1.ToJson(), again.ToJson(), "round trip");

        var h = new History(tmp.File("h.db"));
        h.SaveScan(r1);
        var d1 = r1.ToJson(includeFacts: false);
        var d2 = (JsonObject)d1.DeepClone();
        d2["score"] = r1.Score + 12;
        d2["findings"]!.AsArray().Add(new JsonObject { ["id"] = "new", ["title"] = "New", ["severity"] = "high", ["status"] = "open" });
        var diff = History.Compare(d1, d2);
        Assert.Equal(12, diff.ScoreChange);
        Assert.Equal(["new"], diff.NewFindings.Select(f => Js.Str(f["id"])));
        Assert.Equal("new", Js.Str(History.Compare(d2, d1).ResolvedFindings[0]["id"]));
        Assert.True(History.Compare(null, d1).Empty);
        h.Accept("keep:x", 3, "X");
        Assert.Equal(new Dictionary<string, int> { ["keep:x"] = 3 }, h.AcceptedWidths());
        h.Unaccept("keep:x");
        Assert.Empty(h.AcceptedWidths());
        Assert.Equal(r1.Score, h.Scans()[0].Score);
        JsonAssert.Equal(d1, h.ScanData(h.Scans()[0].Id), "stored scan");
    }

    [Fact]
    public void KeepHidesUntilWider()
    {
        var raw = RawScan.FromJson(Golden.Fixture("this_pc_raw.json"));
        var plain = Analysis.Analyze(raw);
        var f = plain.Finding("exposure.program:spotifylauncher.exe")!;
        var kept = Analysis.Analyze(raw, accepted: new() { [f.KeepKey!] = f.Width });
        Assert.Equal(FindingStatus.Accepted, kept.Finding(f.Id)!.Status);
        Assert.True(kept.Score < plain.Score);
        var narrower = Analysis.Analyze(raw, accepted: new() { [f.KeepKey!] = f.Width - 1 });
        Assert.Equal(FindingStatus.Open, narrower.Finding(f.Id)!.Status);
    }

    [Fact]
    public void ServiceAllowlistExcludesNeverTouch()
    {
        Assert.Empty(Actions.Primitives.ServiceAllowlist.Intersect(KnowledgeBase.Load().NeverTouch));
    }
}
