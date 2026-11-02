using System.Text.Json.Nodes;
using SimplySec.Core.Compat;
using SimplySec.Core.Eval;
using SimplySec.Core.Model;
using SimplySec.Core.Tests.Support;

namespace SimplySec.Core.Tests;

public class ExposureGoldenTests
{
    [Fact]
    public void TableAndRandomCases()
    {
        var failures = new List<string>();
        foreach (var c in Golden.Load("exposure_cases").AsArray())
        {
            var ifaces = c!["interfaces"]!.AsArray().Select(i => NetInterface.FromJson(i!)).ToList();
            var env = c["env"]!.AsObject().ToDictionary(kv => kv.Key, kv => Js.Str(kv.Value), StringComparer.Ordinal);
            var fw = FirewallState.FromJson(c["firewall"]!);
            var lst = Listener.FromJson(c["listener"]!);
            var result = Evaluator.Evaluate(lst, fw, new EvalContext(ifaces, env));
            var diff = JsonAssert.FirstDiff(c["result"], result.ToJson(), "$", []);
            diff ??= JsonAssert.FirstDiff(c["rules"], Js.StrArray(result.Rules), "$.rules", []);
            if (diff is not null)
            {
                failures.Add($"{c["name"]}: {diff}");
            }
        }
        Assert.True(failures.Count == 0, $"{failures.Count} failures:\n" + string.Join("\n", failures.Take(15)));
    }

    [Fact]
    public void ThisPcFixture()
    {
        var raw = Golden.Fixture("this_pc_raw.json");
        var ifaces = raw["interfaces"]!.AsArray().Select(i => NetInterface.FromJson(i!)).ToList();
        var env = raw["env"]!.AsObject().ToDictionary(kv => PyStr.Upper(kv.Key), kv => Js.Str(kv.Value), StringComparer.Ordinal);
        var fw = FirewallState.FromJson(raw["firewall"]!);
        var listeners = raw["listeners"]!.AsArray().Select(l => Listener.FromJson(l!)).ToList();
        var result = Evaluator.EvaluateAll(listeners, fw, new EvalContext(ifaces, env));
        JsonAssert.Equal(Golden.Load("exposure_fixture"), new JsonArray(result.Select(e => (JsonNode)e.ToJson()).ToArray()), "fixture");
    }
}
