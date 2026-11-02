using System.Numerics;
using System.Text.Json.Nodes;
using SimplySec.Core.Compat;
using SimplySec.Core.Eval;
using SimplySec.Core.Net;
using SimplySec.Core.Security;
using SimplySec.Core.Tests.Support;

namespace SimplySec.Core.Tests;

public class PrimitivesGoldenTests
{
    private static JsonNode G => Golden.Load("primitives");

    private static AddrSet Set(JsonNode n) => new(
        Js.Int(n["family"]),
        n["intervals"]!.AsArray().Select(i => (BigInteger.Parse(Js.Str(i![0])), BigInteger.Parse(Js.Str(i[1])))));

    internal static JsonObject Iv(AddrSet s) => new()
    {
        ["family"] = s.Family,
        ["intervals"] = new JsonArray(s.Intervals.Select(i => (JsonNode)new JsonArray(i.Lo.ToString(), i.Hi.ToString())).ToArray()),
    };

    [Fact]
    public void AddrSetAlgebra()
    {
        var i = 0;
        foreach (var c in G["addrsets"]!.AsArray())
        {
            var a = Set(c!["a"]!);
            var b = Set(c["b"]!);
            var ctx = $"case {i++}";
            JsonAssert.Equal(c["a"], Iv(a), ctx + " a");
            JsonAssert.Equal(c["union"], Iv(a.Union(b)), ctx + " union");
            JsonAssert.Equal(c["subtract"], Iv(a.Subtract(b)), ctx + " subtract");
            JsonAssert.Equal(c["intersect"], Iv(a.Intersect(b)), ctx + " intersect");
            Assert.Equal(Js.Bool(c["a_empty"]), a.IsEmpty);
            Assert.Equal(Js.Bool(c["a_everything"]), a.IsEverything);
            Assert.Equal(Js.Bool(c["a_subset_b"]), a.IsSubsetOf(b));
            JsonAssert.Equal(c["a_describe"], Js.StrArray(a.Describe()), ctx + " describe");
            JsonAssert.Equal(c["a_describe_2"], Js.StrArray(a.Describe(2)), ctx + " describe2");
            foreach (var p in c["probes"]!.AsArray())
            {
                Assert.True(Js.Bool(p!["in"]) == a.ContainsIp(Js.Str(p["ip"])), $"{ctx} probe {p["ip"]}");
            }
        }
    }

    [Fact]
    public void ParseLiteral()
    {
        foreach (var c in G["literals"]!.AsArray())
        {
            var token = Js.Str(c!["token"]);
            var r = AddrSet.ParseLiteral(token);
            JsonAssert.Equal(c["result"], r is null ? null : Iv(r), $"token '{token}'");
            if (c["describe"] is JsonNode d)
            {
                JsonAssert.Equal(d, Js.StrArray(r!.Describe()), $"describe '{token}'");
            }
        }
    }

    [Fact]
    public void IpInfo()
    {
        foreach (var c in G["ip_info"]!.AsArray())
        {
            var text = Js.Str(c!["text"]);
            var pct = text.IndexOf('%');
            var ok = PyIp.TryParseAddress(pct >= 0 ? text[..pct] : text, out var ip);
            Assert.True(Js.Bool(c["valid"]) == ok, $"valid '{text}'");
            if (!ok)
            {
                continue;
            }
            Assert.Equal(Js.Int(c["version"]), ip.Family);
            Assert.Equal(Js.Str(c["value"]), ip.Value.ToString());
            Assert.Equal(Js.Str(c["str"]), ip.ToString());
            Assert.True(Js.Bool(c["is_private"]) == ip.IsPrivate, $"is_private '{text}'");
            Assert.True(Js.Bool(c["is_loopback"]) == ip.IsLoopback, $"is_loopback '{text}'");
            Assert.True(Js.Bool(c["is_link_local"]) == ip.IsLinkLocal, $"is_link_local '{text}'");
        }
        foreach (var c in G["iface_info"]!.AsArray())
        {
            var text = Js.Str(c!["text"]);
            var pct = text.IndexOf('%');
            var ok = PyIp.TryParseInterface(pct >= 0 ? text[..pct] : text, out var ii);
            Assert.True(Js.Bool(c["valid"]) == ok, $"iface valid '{text}'");
            if (!ok)
            {
                continue;
            }
            Assert.Equal(Js.Str(c["ip"]), ii.Ip.ToString());
            Assert.Equal(Js.Str(c["network_str"]), ii.Network.ToString());
            JsonAssert.Equal(c["network"], Iv(AddrSet.FromNetwork(ii.Network)), text);
        }
    }

    [Fact]
    public void SddlDecide()
    {
        foreach (var c in G["sddl"]!.AsArray())
        {
            var cond = Sddl.ParseUserCondition(Js.Str(c!["sddl"]));
            var sid = Js.StrOrNull(c["sid"]);
            var ctx = $"{c["sddl"]} / {sid}";
            JsonAssert.Equal(c["allow"], Js.StrArray(cond.Allow.Order(StringComparer.Ordinal)), ctx);
            JsonAssert.Equal(c["deny"], Js.StrArray(cond.Deny.Order(StringComparer.Ordinal)), ctx);
            var expected = Js.IsNull(c["decide"]) ? (bool?)null : Js.Bool(c["decide"]);
            Assert.True(expected == cond.Decide(sid), ctx);
        }
    }

    [Fact]
    public void PortsPathsTitlesFnmatch()
    {
        foreach (var c in G["ports"]!.AsArray())
        {
            var p = Evaluator.ParsePorts(Js.Str(c!["spec"]));
            var actual = new JsonObject
            {
                ["any"] = p.Any,
                ["ranges"] = new JsonArray(p.Ranges.Select(r => (JsonNode)new JsonArray(r.Lo, r.Hi)).ToArray()),
                ["keywords"] = Js.StrArray(p.Keywords),
            };
            JsonAssert.Equal(c, actual, $"ports '{c["spec"]}'", "spec");
        }
        var env = G["paths"]!["env"]!.AsObject().ToDictionary(kv => kv.Key, kv => Js.Str(kv.Value), StringComparer.Ordinal);
        foreach (var c in G["paths"]!["cases"]!.AsArray())
        {
            Assert.Equal(Js.Str(c!["result"]), Evaluator.NormalizeAppPath(Js.Str(c["path"]), env));
        }
        foreach (var c in G["titles"]!.AsArray())
        {
            Assert.Equal(Js.Str(c!["title"]), PyStr.Title(Js.Str(c["text"])));
        }
        foreach (var c in G["fnmatch"]!.AsArray())
        {
            Assert.True(Js.Bool(c!["match"]) == PyStr.FnMatchCase(Js.Str(c["name"]), Js.Str(c["pattern"])), c.ToJsonString());
        }
    }
}
