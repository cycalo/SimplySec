using System.Text.Json.Nodes;
using SimplySec.Core.Checks;
using SimplySec.Core.Compat;
using SimplySec.Core.Engine;
using SimplySec.Core.Model;
using SimplySec.Core.Tests.Support;

namespace SimplySec.Core.Tests;

public class AnalyzeGoldenTests
{
    static AnalyzeGoldenTests() => Pinned.Apply();

    /// <summary>Applies the exporter's two-level patch to the fixture's RawScan dict.</summary>
    internal static RawScan Scenario(JsonNode patch)
    {
        var raw = (JsonObject)Golden.Load("rawscan_roundtrip").DeepClone();
        foreach (var (k, v) in patch["set"]!.AsObject())
        {
            raw[k] = v?.DeepClone();
        }
        var facts = raw["facts"]!.AsObject();
        foreach (var (k, v) in patch["facts"]!.AsObject())
        {
            facts[k] = v?.DeepClone();
        }
        foreach (var k in patch["facts_removed"]!.AsArray())
        {
            facts.Remove(Js.Str(k));
        }
        var fw = raw["firewall"]!.AsObject();
        foreach (var (k, v) in patch["firewall"]!.AsObject())
        {
            fw[k] = v?.DeepClone();
        }
        return RawScan.FromJson(raw);
    }

    internal static Dictionary<string, int> Accepted(JsonNode? n) =>
        (n as JsonObject ?? []).ToDictionary(kv => kv.Key, kv => Js.Int(kv.Value), StringComparer.Ordinal);

    internal static Func<string, bool> FileExists(JsonNode c) =>
        Js.Bool(c["files_missing"]) ? _ => false : Pinned.FileExists;

    [Fact]
    public void RawScanRoundTrip()
    {
        var expected = Golden.Load("rawscan_roundtrip");
        var raw = RawScan.FromJson(Golden.Fixture("this_pc_raw.json"));
        JsonAssert.Equal(expected, raw.ToJson(), "roundtrip");
    }

    [Fact]
    public void AllScenarios()
    {
        var failures = new List<string>();
        var compared = 0;
        foreach (var c in Golden.Load("analyze").AsArray())
        {
            var name = Js.Str(c!["name"]);
            compared += c["result"]!["findings"]!.AsArray().Count;
            try
            {
                var raw = Scenario(c["raw_patch"]!);
                var result = Analysis.Analyze(raw, accepted: Accepted(c["accepted"]), fileExists: FileExists(c));
                var diff = JsonAssert.FirstDiff(c["result"], result.ToJson(includeFacts: false), "$", ["version"]);
                if (diff is not null)
                {
                    failures.Add($"{name}: {diff}");
                }
            }
            catch (Exception e)
            {
                failures.Add($"{name}: {e.GetType().Name}: {e.Message}");
            }
        }
        Assert.True(failures.Count == 0, $"{failures.Count} scenario(s) differ:\n" + string.Join("\n", failures.Take(12)));
    }

    private static JsonObject PlanJson(Plan plan) => new()
    {
        ["items"] = new JsonArray(plan.Items.Select(i => (JsonNode)new JsonObject
        {
            ["fix_id"] = i.Fix.Id,
            ["params"] = i.Params.DeepClone(),
            ["finding_id"] = i.FindingId,
            ["specs"] = new JsonArray(i.Specs.Select(s => (JsonNode)s.ToJson()).ToArray()),
            ["warnings"] = new JsonArray(i.Warnings.Select(w => (JsonNode)w.ToJson()).ToArray()),
            ["impact"] = i.Impact?.ToJson(),
        }).ToArray()),
        ["refused"] = Js.StrArray(plan.Refused),
        ["might_break"] = Js.StrArray(plan.MightBreak),
        ["touches_firewall"] = plan.TouchesFirewall,
    };

    [Fact]
    public void AllPlans()
    {
        var failures = new List<string>();
        var planned = 0;
        var analyses = Golden.Load("analyze").AsArray().ToDictionary(a => Js.Str(a!["name"]), a => a!);
        foreach (var p in Golden.Load("plans").AsArray())
        {
            var name = Js.Str(p!["name"]);
            var c = analyses[name];
            try
            {
                var raw = Scenario(c["raw_patch"]!);
                var (result, ctx) = Analysis.AnalyzeWithContext(raw, accepted: Accepted(c["accepted"]), fileExists: FileExists(c));
                foreach (var item in p["per_option"]!.AsArray())
                {
                    var f = result.Finding(Js.Str(item!["finding_id"]))!;
                    var opt = f.Fixes.First(o => o.FixId == Js.Str(item["fix_id"]));
                    var plan = Analysis.BuildPlan([new Selection(opt.FixId, opt.Params, f.Id)], ctx);
                    planned++;
                    var diff = JsonAssert.FirstDiff(item["plan"], PlanJson(plan), "$", []);
                    if (diff is not null)
                    {
                        failures.Add($"{name} {f.Id} {opt.FixId}: {diff}");
                    }
                }
                List<Selection> extra =
                [
                    new("no.such_fix"),
                    new("sharing.review"),
                    new("network.mark_private", new JsonObject { ["index"] = 9, ["alias"] = "Ethernet", ["name"] = "EE-G9QKJQ" }),
                    new("exposure.block_program_public", new JsonObject { ["exe"] = @"C:\x\a.exe", ["label"] = "A" }),
                ];
                var d1 = JsonAssert.FirstDiff(p["extra"], PlanJson(Analysis.BuildPlan(extra, ctx)), "$", []);
                var d2 = JsonAssert.FirstDiff(p["extra_no_ctx"], PlanJson(Analysis.BuildPlan(extra[..2], null)), "$", []);
                var (sels, skipped) = Analysis.RecommendedSplit(result);
                var rec = new JsonArray(sels.Select(s => (JsonNode)new JsonObject
                {
                    ["fix_id"] = s.FixId,
                    ["params"] = s.Params.DeepClone(),
                    ["finding_id"] = s.FindingId,
                }).ToArray());
                var d3 = JsonAssert.FirstDiff(p["recommended"], rec, "$", []);
                var d4 = JsonAssert.FirstDiff(p["skipped"], new JsonArray(skipped.Select(x => (JsonNode)new JsonArray(x.Item1, x.Item2)).ToArray()), "$", []);
                foreach (var d in new[] { d1, d2, d3, d4 })
                {
                    if (d is not null)
                    {
                        failures.Add($"{name}: {d}");
                    }
                }
            }
            catch (Exception e)
            {
                failures.Add($"{name}: {e.GetType().Name}: {e.Message}");
            }
        }
        Assert.True(failures.Count == 0, $"{failures.Count} plan difference(s):\n" + string.Join("\n", failures.Take(12)));
    }
}

/// <summary>The same pinned clock, rule id and file_exists as tools/parity/export_golden.py.</summary>
public static class Pinned
{
    public static readonly DateTimeOffset Now = new(2026, 11, 2, 12, 0, 0, TimeSpan.Zero);

    private sealed class FixedClock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
        public override TimeZoneInfo LocalTimeZone => TimeZoneInfo.Utc;
    }

    public static void Apply()
    {
        Ambient.Clock = new FixedClock();
        Ambient.RuleToken = () => "0000abcd";
    }

    public static bool FileExists(string path) => !PyStr.Lower(path).Contains("\\missing\\", StringComparison.Ordinal);
}
