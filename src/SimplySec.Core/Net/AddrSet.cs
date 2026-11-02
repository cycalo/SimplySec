using System.Numerics;
using SimplySec.Core.Compat;

namespace SimplySec.Core.Net;

/// <summary>
/// A set of IP addresses for one family, stored as sorted, disjoint, inclusive intervals.
/// BigInteger keeps Python's unbounded-integer semantics (no overflow at the top of the range).
/// </summary>
public sealed class AddrSet : IEquatable<AddrSet>
{
    public int Family { get; }
    public IReadOnlyList<(BigInteger Lo, BigInteger Hi)> Intervals { get; }

    public AddrSet(int family, IEnumerable<(BigInteger Lo, BigInteger Hi)>? intervals = null)
    {
        Family = family;
        Intervals = Normalise(intervals ?? []);
    }

    private static List<(BigInteger, BigInteger)> Normalise(IEnumerable<(BigInteger Lo, BigInteger Hi)> intervals)
    {
        var sorted = intervals.Where(i => i.Lo <= i.Hi).OrderBy(i => i.Lo).ThenBy(i => i.Hi).ToList();
        var output = new List<(BigInteger, BigInteger)>();
        foreach (var (lo, hi) in sorted)
        {
            if (output.Count > 0 && lo <= output[^1].Item2 + 1)
            {
                output[^1] = (output[^1].Item1, BigInteger.Max(output[^1].Item2, hi));
            }
            else
            {
                output.Add((lo, hi));
            }
        }
        return output;
    }

    public static AddrSet Everything(int family) => new(family, [(BigInteger.Zero, PyIp.MaxOf(family))]);
    public static AddrSet Empty(int family) => new(family);
    public static AddrSet FromNetwork(IpNet net) => new(net.Family, [(net.Network, net.Broadcast)]);

    public static AddrSet Loopback(int family)
    {
        var text = family == 4 ? "127.0.0.0/8" : "::1/128";
        PyIp.TryParseNetwork(text, out var net);
        return FromNetwork(net);
    }

    private void Check(AddrSet other)
    {
        if (other.Family != Family)
        {
            throw new ArgumentException("address family mismatch");
        }
    }

    public AddrSet Union(AddrSet other)
    {
        Check(other);
        return new AddrSet(Family, Intervals.Concat(other.Intervals));
    }

    public AddrSet Subtract(AddrSet other)
    {
        Check(other);
        var result = new List<(BigInteger, BigInteger)>();
        foreach (var (lo, hi) in Intervals)
        {
            var cur = lo;
            foreach (var (clo, chi) in other.Intervals)
            {
                if (chi < cur || clo > hi)
                {
                    continue;
                }
                if (clo > cur)
                {
                    result.Add((cur, clo - 1));
                }
                cur = BigInteger.Max(cur, chi + 1);
                if (cur > hi)
                {
                    break;
                }
            }
            if (cur <= hi)
            {
                result.Add((cur, hi));
            }
        }
        return new AddrSet(Family, result);
    }

    public AddrSet Intersect(AddrSet other) => Subtract(Subtract(other));

    public bool IsEmpty => Intervals.Count == 0;

    public bool IsEverything =>
        Intervals.Count == 1 && Intervals[0].Lo.IsZero && Intervals[0].Hi == PyIp.MaxOf(Family);

    public bool IsSubsetOf(AddrSet other) => Subtract(other).IsEmpty;

    public bool ContainsIp(string ip)
    {
        var at = ip.IndexOf('%');
        if (!PyIp.TryParseAddress(at >= 0 ? ip[..at] : ip, out var addr))
        {
            return false;
        }
        // Python compares the integer value only (any family).
        return Intervals.Any(i => i.Lo <= addr.Value && addr.Value <= i.Hi);
    }

    public bool Equals(AddrSet? other) =>
        other is not null && other.Family == Family && Intervals.SequenceEqual(other.Intervals);

    public override bool Equals(object? obj) => Equals(obj as AddrSet);

    public override int GetHashCode()
    {
        var h = new HashCode();
        h.Add(Family);
        foreach (var i in Intervals)
        {
            h.Add(i.Lo);
            h.Add(i.Hi);
        }
        return h.ToHashCode();
    }

    public List<string> Describe(int limit = 6)
    {
        if (IsEverything)
        {
            return ["any address"];
        }
        var parts = new List<string>();
        foreach (var (lo, hi) in Intervals)
        {
            var nets = PyIp.Summarize(Family, lo, hi);
            if (nets.Count <= 2)
            {
                foreach (var n in nets)
                {
                    parts.Add(n.NumAddresses > 1 ? n.ToString() : PyIp.Format(Family, n.Network));
                }
            }
            else
            {
                parts.Add($"{PyIp.Format(Family, lo)}-{PyIp.Format(Family, hi)}");
            }
        }
        if (parts.Count > limit)
        {
            var shown = parts.Take(limit).ToList();
            shown.Add($"+{parts.Count - limit} more");
            return shown;
        }
        return parts;
    }

    /// <summary>
    /// One firewall address token that is not a keyword: single address, CIDR, dotted mask or
    /// range. Null when the token is not a literal address.
    /// </summary>
    public static AddrSet? ParseLiteral(string token)
    {
        token = PyStr.Strip(token);
        if (token.Length == 0)
        {
            return null;
        }
        if (token.Contains('-') && !token.Contains('/'))
        {
            var dash = token.IndexOf('-');
            if (!PyIp.TryParseAddress(token[..dash], out var lo) || !PyIp.TryParseAddress(token[(dash + 1)..], out var hi))
            {
                return null;
            }
            if (lo.Family != hi.Family)
            {
                return null;
            }
            return new AddrSet(lo.Family, [(lo.Value, hi.Value)]);
        }
        if (token.Contains('/'))
        {
            var slash = token.IndexOf('/');
            var addr = token[..slash];
            var mask = token[(slash + 1)..];
            IpNet net;
            if (mask.Contains('.') || mask.Contains(':'))
            {
                if (!PyIp.TryParseNetwork($"{addr}/{mask}", out net))
                {
                    return null;
                }
            }
            else
            {
                if (!PyIp.TryPyInt(mask, out var bits))
                {
                    return null;
                }
                if (!PyIp.TryParseNetwork($"{addr}/{bits.ToString(System.Globalization.CultureInfo.InvariantCulture)}", out net))
                {
                    return null;
                }
            }
            return FromNetwork(net);
        }
        var pct = token.IndexOf('%');
        if (!PyIp.TryParseAddress(pct >= 0 ? token[..pct] : token, out var ip))
        {
            return null;
        }
        return new AddrSet(ip.Family, [(ip.Value, ip.Value)]);
    }
}
