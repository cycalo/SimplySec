using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SimplySec.Core.Compat;

/// <summary>
/// Helpers for untyped JSON data (facts, fix params, impacts) with Python dict semantics:
/// missing keys fall back to defaults, PowerShell's single-or-array quirk is handled by AsList,
/// and truthiness follows Python's rules.
/// </summary>
public static class Js
{
    public static readonly JsonSerializerOptions Compact = new() { WriteIndented = false };

    public static JsonNode? Get(JsonNode? node, string key) =>
        node is JsonObject o && o.TryGetPropertyValue(key, out var v) ? v : null;

    public static bool Has(JsonNode? node, string key) => node is JsonObject o && o.ContainsKey(key);

    public static string Str(JsonNode? n, string def = "")
    {
        if (n is null)
        {
            return def;
        }
        if (n is JsonValue v)
        {
            if (v.TryGetValue<string>(out var s))
            {
                return s;
            }
            return PyRepr(n);
        }
        return PyRepr(n);
    }

    public static string? StrOrNull(JsonNode? n) => n is null ? null : Str(n);

    /// <summary>The numeric value of a JSON number, whatever CLR type backs it.</summary>
    public static bool TryNumber(JsonNode? n, out double d, out long? l)
    {
        d = 0;
        l = null;
        if (n is not JsonValue v)
        {
            return false;
        }
        if (v.TryGetValue<JsonElement>(out var el))
        {
            if (el.ValueKind != JsonValueKind.Number)
            {
                return false;
            }
            if (el.TryGetInt64(out var li))
            {
                l = li;
                d = li;
                return true;
            }
            d = el.GetDouble();
            return true;
        }
        if (v.TryGetValue<int>(out var i)) { l = i; d = i; return true; }
        if (v.TryGetValue<long>(out var lo)) { l = lo; d = lo; return true; }
        if (v.TryGetValue<uint>(out var ui)) { l = ui; d = ui; return true; }
        if (v.TryGetValue<short>(out var sh)) { l = sh; d = sh; return true; }
        if (v.TryGetValue<ushort>(out var us)) { l = us; d = us; return true; }
        if (v.TryGetValue<byte>(out var by)) { l = by; d = by; return true; }
        if (v.TryGetValue<ulong>(out var ul)) { d = ul; if (ul <= long.MaxValue) { l = (long)ul; } return true; }
        if (v.TryGetValue<double>(out var db)) { d = db; return true; }
        if (v.TryGetValue<float>(out var fl)) { d = fl; return true; }
        if (v.TryGetValue<decimal>(out var de)) { d = (double)de; if (de == decimal.Truncate(de)) { l = (long)de; } return true; }
        return false;
    }

    public static long Long(JsonNode? n, long def = 0)
    {
        if (n is JsonValue v)
        {
            if (TryNumber(v, out var d, out var l))
            {
                return l ?? (long)d;
            }
            if (v.TryGetValue<bool>(out var b))
            {
                return b ? 1 : 0;
            }
            if (v.TryGetValue<string>(out var s) && long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var p))
            {
                return p;
            }
        }
        return def;
    }

    public static int Int(JsonNode? n, int def = 0) => (int)Long(n, def);

    public static double? Double(JsonNode? n)
    {
        if (n is JsonValue v)
        {
            if (TryNumber(v, out var d, out _))
            {
                return d;
            }
            if (v.TryGetValue<bool>(out var b))
            {
                return b ? 1 : 0;
            }
        }
        return null;
    }

    public static bool Bool(JsonNode? n, bool def = false) => n is null ? def : Truthy(n);

    public static bool IsNumber(JsonNode? n) =>
        n is JsonValue v && v.GetValueKind() == JsonValueKind.Number;

    /// <summary>Python int check that excludes bool (stricter than isinstance(x, int)).</summary>
    public static bool IsInt(JsonNode? n) =>
        n is JsonValue v && v.GetValueKind() == JsonValueKind.Number && TryNumber(v, out _, out var l) && l is not null;

    public static bool IsBool(JsonNode? n) =>
        n is JsonValue v && v.GetValueKind() is JsonValueKind.True or JsonValueKind.False;

    public static bool IsString(JsonNode? n) =>
        n is JsonValue v && v.GetValueKind() == JsonValueKind.String;

    /// <summary>Python truthiness.</summary>
    public static bool Truthy(JsonNode? n)
    {
        switch (n)
        {
            case null:
                return false;
            case JsonArray a:
                return a.Count > 0;
            case JsonObject o:
                return o.Count > 0;
            case JsonValue v:
                switch (v.GetValueKind())
                {
                    case JsonValueKind.True:
                        return true;
                    case JsonValueKind.False:
                    case JsonValueKind.Null:
                        return false;
                    case JsonValueKind.String:
                        return v.GetValue<string>().Length > 0;
                    case JsonValueKind.Number:
                        return Double(v) != 0;
                    default:
                        return true;
                }
            default:
                return true;
        }
    }

    /// <summary><c>util.as_list</c>: PowerShell turns 1-item arrays into objects and empty arrays into {} or null.</summary>
    public static List<JsonNode?> AsList(JsonNode? value)
    {
        if (value is null || (value is JsonObject o && o.Count == 0))
        {
            return [];
        }
        if (value is JsonArray a)
        {
            return [.. a];
        }
        if (value is JsonValue v && v.GetValueKind() == JsonValueKind.Null)
        {
            return [];
        }
        return [value];
    }

    /// <summary>Python <c>==</c> between a JSON value and a number (bools count as 0/1).</summary>
    public static bool NumEquals(JsonNode? n, double value)
    {
        if (n is JsonValue v && v.GetValueKind() is JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False)
        {
            return Double(v) == value;
        }
        return false;
    }

    /// <summary>Python equality for JSON trees (1 == 1.0 == True).</summary>
    public static bool PyEquals(JsonNode? a, JsonNode? b)
    {
        if (a is null || b is null)
        {
            return IsNull(a) && IsNull(b);
        }
        if (a is JsonObject oa)
        {
            if (b is not JsonObject ob || oa.Count != ob.Count)
            {
                return false;
            }
            foreach (var (k, v) in oa)
            {
                if (!ob.TryGetPropertyValue(k, out var w) || !PyEquals(v, w))
                {
                    return false;
                }
            }
            return true;
        }
        if (a is JsonArray aa)
        {
            if (b is not JsonArray ab || aa.Count != ab.Count)
            {
                return false;
            }
            for (var i = 0; i < aa.Count; i++)
            {
                if (!PyEquals(aa[i], ab[i]))
                {
                    return false;
                }
            }
            return true;
        }
        if (b is JsonObject || b is JsonArray)
        {
            return false;
        }
        var ka = ((JsonValue)a).GetValueKind();
        var kb = ((JsonValue)b).GetValueKind();
        if (ka == JsonValueKind.Null || kb == JsonValueKind.Null)
        {
            return ka == kb;
        }
        if (ka == JsonValueKind.String || kb == JsonValueKind.String)
        {
            return ka == kb && a.GetValue<string>() == b.GetValue<string>();
        }
        return Double(a) == Double(b);
    }

    public static bool IsNull(JsonNode? n) =>
        n is null || (n is JsonValue v && v.GetValueKind() == JsonValueKind.Null);

    public static JsonNode? Clone(JsonNode? n) => n?.DeepClone();

    public static JsonObject CloneObj(JsonObject? o) => (JsonObject?)o?.DeepClone() ?? [];

    public static JsonArray StrArray(IEnumerable<string> items)
    {
        var a = new JsonArray();
        foreach (var s in items)
        {
            a.Add(JsonValue.Create(s));
        }
        return a;
    }

    public static List<string> StrList(JsonNode? n) =>
        n is JsonArray a ? a.Select(x => Str(x)).ToList() : [];

    public static List<string>? StrListOrNull(JsonNode? n) => IsNull(n) ? null : StrList(n);

    public static JsonNode? Of(string? s) => s is null ? null : JsonValue.Create(s);

    /// <summary>Python's <c>str()</c> of a JSON value (repr-like for containers).</summary>
    public static string PyRepr(JsonNode? n)
    {
        switch (n)
        {
            case null:
                return "None";
            case JsonValue v:
                switch (v.GetValueKind())
                {
                    case JsonValueKind.True:
                        return "True";
                    case JsonValueKind.False:
                        return "False";
                    case JsonValueKind.Null:
                        return "None";
                    case JsonValueKind.String:
                        return v.GetValue<string>();
                    case JsonValueKind.Number:
                        TryNumber(v, out var dv, out var lv);
                        if (lv is not null && !IsFloatText(v))
                        {
                            return lv.Value.ToString(CultureInfo.InvariantCulture);
                        }
                        return PyFloat(dv);
                }
                return v.ToJsonString();
            case JsonArray a:
                return "[" + string.Join(", ", a.Select(ReprInner)) + "]";
            case JsonObject o:
                return "{" + string.Join(", ", o.Select(kv => $"'{kv.Key}': {ReprInner(kv.Value)}")) + "}";
        }
        return n.ToJsonString();
    }

    private static string ReprInner(JsonNode? n) =>
        n is JsonValue v && v.GetValueKind() == JsonValueKind.String ? $"'{v.GetValue<string>()}'" : PyRepr(n);

    private static bool IsFloatText(JsonValue v)
    {
        if (v.TryGetValue<JsonElement>(out var el))
        {
            var raw = el.GetRawText();
            return raw.Contains('.') || raw.Contains('e') || raw.Contains('E');
        }
        return v.TryGetValue<double>(out _) || v.TryGetValue<float>(out _);
    }

    /// <summary>Python's repr of a float (shortest round-trip, ".0" for integral values).</summary>
    public static string PyFloat(double d)
    {
        if (double.IsNaN(d))
        {
            return "nan";
        }
        if (double.IsInfinity(d))
        {
            return d > 0 ? "inf" : "-inf";
        }
        var s = d.ToString("R", CultureInfo.InvariantCulture);
        if (s.Contains('E'))
        {
            s = s.Replace("E+", "e+", StringComparison.Ordinal).Replace("E-", "e-", StringComparison.Ordinal);
            return s;
        }
        if (!s.Contains('.'))
        {
            s += ".0";
        }
        return s;
    }
}
