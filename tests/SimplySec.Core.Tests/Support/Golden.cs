using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SimplySec.Core.Compat;

namespace SimplySec.Core.Tests.Support;

/// <summary>Loads golden data exported from Python v2 (tools/parity/export_golden.py).</summary>
public static class Golden
{
    public static readonly string RepoRoot = FindRoot();

    private static string FindRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "SimplySec.slnx")))
        {
            dir = dir.Parent;
        }
        return dir?.FullName ?? throw new InvalidOperationException("repo root not found");
    }

    private static readonly Dictionary<string, JsonNode> Cache = [];

    public static JsonNode Load(string name)
    {
        lock (Cache)
        {
            if (!Cache.TryGetValue(name, out var node))
            {
                var path = Path.Combine(RepoRoot, "tests", "golden", name + ".json.gz");
                using var fs = File.OpenRead(path);
                using var gz = new GZipStream(fs, CompressionMode.Decompress);
                node = JsonNode.Parse(gz, documentOptions: new JsonDocumentOptions { MaxDepth = 256 })!;
                Cache[name] = node;
            }
            return node;
        }
    }

    public static JsonNode Fixture(string name)
    {
        var path = Path.Combine(RepoRoot, "tests", "fixtures", name);
        return JsonNode.Parse(File.ReadAllText(path, Encoding.UTF8))!;
    }
}

/// <summary>Semantic JSON comparison with the path of the first difference.</summary>
public static class JsonAssert
{
    public static void Equal(JsonNode? expected, JsonNode? actual, string context = "", params string[] ignore)
    {
        var diff = FirstDiff(expected, actual, "$", new HashSet<string>(ignore, StringComparer.Ordinal));
        if (diff is not null)
        {
            Assert.Fail($"{context}: {diff}");
        }
    }

    public static string? FirstDiff(JsonNode? e, JsonNode? a, string path, HashSet<string> ignore)
    {
        if (Js.IsNull(e) || Js.IsNull(a))
        {
            return Js.IsNull(e) && Js.IsNull(a) ? null : $"{path}: expected {Show(e)}, got {Show(a)}";
        }
        switch (e)
        {
            case JsonObject eo:
                if (a is not JsonObject ao)
                {
                    return $"{path}: expected object, got {Show(a)}";
                }
                foreach (var (k, v) in eo)
                {
                    if (ignore.Contains(k))
                    {
                        continue;
                    }
                    if (!ao.TryGetPropertyValue(k, out var av))
                    {
                        return $"{path}.{k}: missing (expected {Show(v)})";
                    }
                    var d = FirstDiff(v, av, $"{path}.{k}", ignore);
                    if (d is not null)
                    {
                        return d;
                    }
                }
                foreach (var (k, v) in ao)
                {
                    if (!ignore.Contains(k) && !eo.ContainsKey(k))
                    {
                        return $"{path}.{k}: unexpected key (value {Show(v)})";
                    }
                }
                return null;
            case JsonArray ea:
                if (a is not JsonArray aa)
                {
                    return $"{path}: expected array, got {Show(a)}";
                }
                for (var i = 0; i < Math.Min(ea.Count, aa.Count); i++)
                {
                    var d = FirstDiff(ea[i], aa[i], $"{path}[{i}]", ignore);
                    if (d is not null)
                    {
                        return d;
                    }
                }
                return ea.Count == aa.Count ? null : $"{path}: expected {ea.Count} items, got {aa.Count}";
            default:
                return Js.PyEquals(e, a) && KindMatches(e!, a!) ? null : $"{path}: expected {Show(e)}, got {Show(a)}";
        }
    }

    private static bool KindMatches(JsonNode e, JsonNode a)
    {
        var ke = e.GetValueKind();
        var ka = a.GetValueKind();
        bool IsBool(JsonValueKind k) => k is JsonValueKind.True or JsonValueKind.False;
        return IsBool(ke) == IsBool(ka);
    }

    private static string Show(JsonNode? n)
    {
        var s = n?.ToJsonString() ?? "null";
        return s.Length > 300 ? s[..300] + "…" : s;
    }
}
