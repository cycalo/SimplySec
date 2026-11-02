using System.Globalization;
using System.Numerics;
using System.Text;

namespace SimplySec.Core.Compat;

/// <summary>An IP address as Python's <c>ipaddress</c> sees it: family 4 or 6 and an integer value.</summary>
public readonly record struct IpAddr(int Family, BigInteger Value, string? Scope = null)
{
    public bool IsLoopback => PyIp.IsLoopback(this);
    public bool IsPrivate => PyIp.IsPrivate(this);
    public bool IsLinkLocal => PyIp.IsLinkLocal(this);
    public override string ToString() => PyIp.Format(this);
}

/// <summary>An IP network (address + prefix length), like <c>ipaddress.IPv4Network</c>.</summary>
public readonly record struct IpNet(int Family, BigInteger Network, int Prefix)
{
    public int MaxPrefix => Family == 4 ? 32 : 128;
    public BigInteger Broadcast => Network | PyIp.HostMask(Family, Prefix);
    public BigInteger NumAddresses => BigInteger.One << (MaxPrefix - Prefix);
    public override string ToString() => $"{PyIp.Format(new IpAddr(Family, Network))}/{Prefix.ToString(CultureInfo.InvariantCulture)}";
}

/// <summary>An interface address (address + its network), like <c>ipaddress.ip_interface</c>.</summary>
public readonly record struct IpIface(IpAddr Ip, IpNet Network)
{
    public int Family => Ip.Family;
}

/// <summary>
/// Python 3.11 <c>ipaddress</c> semantics: strict parsing (no leading zeros, no shorthand),
/// formatting, and the special-purpose tables (is_private, is_loopback, ...).
/// </summary>
public static class PyIp
{
    public static readonly BigInteger Max4 = (BigInteger.One << 32) - 1;
    public static readonly BigInteger Max6 = (BigInteger.One << 128) - 1;

    public static BigInteger MaxOf(int family) => family == 4 ? Max4 : Max6;

    public static BigInteger HostMask(int family, int prefix) =>
        (BigInteger.One << ((family == 4 ? 32 : 128) - prefix)) - 1;

    public static BigInteger NetMask(int family, int prefix) => MaxOf(family) ^ HostMask(family, prefix);

    // ------------------------------------------------------------------ parsing

    /// <summary><c>ipaddress.ip_address(text)</c>; false where Python raises ValueError.</summary>
    public static bool TryParseAddress(string text, out IpAddr addr)
    {
        if (TryParseV4(text, out var v4))
        {
            addr = new IpAddr(4, v4);
            return true;
        }
        if (TryParseV6Address(text, out addr))
        {
            return true;
        }
        addr = default;
        return false;
    }

    public static IpAddr? ParseAddress(string text) => TryParseAddress(text, out var a) ? a : null;

    internal static bool TryParseV4(string text, out BigInteger value)
    {
        value = 0;
        if (string.IsNullOrEmpty(text) || text.Contains('/'))
        {
            return false;
        }
        var octets = text.Split('.');
        if (octets.Length != 4)
        {
            return false;
        }
        uint result = 0;
        foreach (var o in octets)
        {
            if (o.Length == 0 || o.Length > 3 || !o.All(char.IsAsciiDigit))
            {
                return false;
            }
            if (o != "0" && o[0] == '0')
            {
                return false;
            }
            var n = int.Parse(o, NumberStyles.None, CultureInfo.InvariantCulture);
            if (n > 255)
            {
                return false;
            }
            result = (result << 8) | (uint)n;
        }
        value = result;
        return true;
    }

    private static bool TryParseV6Address(string text, out IpAddr addr)
    {
        addr = default;
        if (string.IsNullOrEmpty(text) || text.Contains('/'))
        {
            return false;
        }
        string? scope = null;
        var pct = text.IndexOf('%');
        var core = text;
        if (pct >= 0)
        {
            scope = text[(pct + 1)..];
            core = text[..pct];
            if (scope.Length == 0 || scope.Contains('%'))
            {
                return false;
            }
        }
        if (!TryParseV6Int(core, out var v))
        {
            return false;
        }
        addr = new IpAddr(6, v, scope);
        return true;
    }

    private static bool TryParseV6Int(string ipStr, out BigInteger value)
    {
        value = 0;
        if (ipStr.Length == 0)
        {
            return false;
        }
        var parts = ipStr.Split(':').ToList();
        if (parts.Count < 3)
        {
            return false;
        }
        if (parts[^1].Contains('.'))
        {
            if (!TryParseV4(parts[^1], out var v4))
            {
                return false;
            }
            parts.RemoveAt(parts.Count - 1);
            var i4 = (uint)v4;
            parts.Add(((i4 >> 16) & 0xFFFF).ToString("x", CultureInfo.InvariantCulture));
            parts.Add((i4 & 0xFFFF).ToString("x", CultureInfo.InvariantCulture));
        }
        const int hextets = 8;
        if (parts.Count > hextets + 1)
        {
            return false;
        }
        int? skip = null;
        for (var i = 1; i < parts.Count - 1; i++)
        {
            if (parts[i].Length == 0)
            {
                if (skip is not null)
                {
                    return false;
                }
                skip = i;
            }
        }
        int partsHi, partsLo, partsSkipped;
        if (skip is not null)
        {
            partsHi = skip.Value;
            partsLo = parts.Count - skip.Value - 1;
            if (parts[0].Length == 0)
            {
                partsHi -= 1;
                if (partsHi != 0)
                {
                    return false;
                }
            }
            if (parts[^1].Length == 0)
            {
                partsLo -= 1;
                if (partsLo != 0)
                {
                    return false;
                }
            }
            partsSkipped = hextets - (partsHi + partsLo);
            if (partsSkipped < 1)
            {
                return false;
            }
        }
        else
        {
            if (parts.Count != hextets || parts[0].Length == 0 || parts[^1].Length == 0)
            {
                return false;
            }
            partsHi = parts.Count;
            partsLo = 0;
            partsSkipped = 0;
        }
        BigInteger ip = 0;
        for (var i = 0; i < partsHi; i++)
        {
            if (!TryHextet(parts[i], out var h))
            {
                return false;
            }
            ip = (ip << 16) | h;
        }
        ip <<= 16 * partsSkipped;
        for (var i = parts.Count - partsLo; i < parts.Count; i++)
        {
            if (!TryHextet(parts[i], out var h))
            {
                return false;
            }
            ip = (ip << 16) | h;
        }
        value = ip;
        return true;
    }

    private static bool TryHextet(string s, out int value)
    {
        value = 0;
        if (s.Length == 0 || s.Length > 4 || !s.All(char.IsAsciiHexDigit))
        {
            return false;
        }
        value = int.Parse(s, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
        return true;
    }

    /// <summary><c>ipaddress.ip_network(text, strict=False)</c>.</summary>
    public static bool TryParseNetwork(string text, out IpNet net)
    {
        net = default;
        var bits = text.Split('/');
        if (bits.Length > 2)
        {
            return false;
        }
        var addrText = bits[0];
        var mask = bits.Length == 2 ? bits[1] : null;
        // IPv4 first, as Python does.
        if (TryParseV4(addrText, out var v4))
        {
            if (!TryV4Prefix(mask, out var p))
            {
                return false;
            }
            net = new IpNet(4, v4 & NetMask(4, p), p);
            return true;
        }
        if (TryParseV6Address(addrText, out var a6))
        {
            int p6 = 128;
            if (mask is not null && !TryPrefixString(mask, 128, out p6))
            {
                return false;
            }
            net = new IpNet(6, a6.Value & NetMask(6, p6), p6);
            return true;
        }
        return false;
    }

    /// <summary><c>ipaddress.ip_interface(text)</c>.</summary>
    public static bool TryParseInterface(string text, out IpIface iface)
    {
        iface = default;
        var bits = text.Split('/');
        if (bits.Length > 2)
        {
            return false;
        }
        var mask = bits.Length == 2 ? bits[1] : null;
        if (TryParseV4(bits[0], out var v4))
        {
            if (!TryV4Prefix(mask, out var p))
            {
                return false;
            }
            iface = new IpIface(new IpAddr(4, v4), new IpNet(4, v4 & NetMask(4, p), p));
            return true;
        }
        if (TryParseV6Address(bits[0], out var a6))
        {
            int p6 = 128;
            if (mask is not null && !TryPrefixString(mask, 128, out p6))
            {
                return false;
            }
            iface = new IpIface(a6, new IpNet(6, a6.Value & NetMask(6, p6), p6));
            return true;
        }
        return false;
    }

    private static bool TryV4Prefix(string? mask, out int prefix)
    {
        if (mask is null)
        {
            prefix = 32;
            return true;
        }
        if (TryPrefixString(mask, 32, out prefix))
        {
            return true;
        }
        // A netmask (255.255.255.0) or a hostmask (0.0.0.255).
        if (!TryParseV4(mask, out var m))
        {
            return false;
        }
        if (TryPrefixFromInt(m, 32, out prefix))
        {
            return true;
        }
        return TryPrefixFromInt(m ^ Max4, 32, out prefix);
    }

    private static bool TryPrefixString(string s, int max, out int prefix)
    {
        prefix = 0;
        if (s.Length == 0 || !s.All(char.IsAsciiDigit))
        {
            return false;
        }
        if (!int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out prefix))
        {
            return false;
        }
        return prefix >= 0 && prefix <= max;
    }

    private static bool TryPrefixFromInt(BigInteger ipInt, int bits, out int prefix)
    {
        var trailing = RightZeroBits(ipInt, bits);
        prefix = bits - trailing;
        var leadingOnes = ipInt >> trailing;
        var allOnes = (BigInteger.One << prefix) - 1;
        return leadingOnes == allOnes;
    }

    internal static int RightZeroBits(BigInteger number, int bits)
    {
        if (number.IsZero)
        {
            return bits;
        }
        var v = ~number & (number - 1);
        return Math.Min(bits, BitLength(v));
    }

    internal static int BitLength(BigInteger v) => v.Sign <= 0 ? 0 : (int)v.GetBitLength();

    /// <summary>Python's <c>int(text)</c> for a prefix written after "/" (whitespace and sign allowed).</summary>
    public static bool TryPyInt(string text, out int value)
    {
        value = 0;
        var t = text.Trim();
        if (t.Length == 0)
        {
            return false;
        }
        var sign = 1;
        if (t[0] is '+' or '-')
        {
            sign = t[0] == '-' ? -1 : 1;
            t = t[1..];
        }
        if (t.Length == 0 || t[0] == '_' || t[^1] == '_' || t.Contains("__", StringComparison.Ordinal))
        {
            return false;
        }
        t = t.Replace("_", "", StringComparison.Ordinal);
        if (!t.All(char.IsAsciiDigit) || t.Length > 9)
        {
            return false;
        }
        value = sign * int.Parse(t, NumberStyles.None, CultureInfo.InvariantCulture);
        return true;
    }

    // ------------------------------------------------------------------ formatting

    public static string Format(IpAddr a)
    {
        var s = a.Family == 4 ? FormatV4(a.Value) : FormatV6(a.Value);
        return a.Scope is null ? s : $"{s}%{a.Scope}";
    }

    public static string Format(int family, BigInteger value) =>
        family == 4 ? FormatV4(value) : FormatV6(value);

    private static string FormatV4(BigInteger v)
    {
        var u = (uint)v;
        return string.Create(CultureInfo.InvariantCulture, $"{u >> 24}.{(u >> 16) & 0xFF}.{(u >> 8) & 0xFF}.{u & 0xFF}");
    }

    private static string FormatV6(BigInteger v)
    {
        var hextets = new List<string>(8);
        for (var i = 7; i >= 0; i--)
        {
            var h = (int)((v >> (16 * i)) & 0xFFFF);
            hextets.Add(h.ToString("x", CultureInfo.InvariantCulture));
        }
        // Python's _compress_hextets: longest run (>1) of "0", first one on ties.
        int bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
        for (var i = 0; i < hextets.Count; i++)
        {
            if (hextets[i] == "0")
            {
                curLen++;
                if (curStart == -1)
                {
                    curStart = i;
                }
                if (curLen > bestLen)
                {
                    bestLen = curLen;
                    bestStart = curStart;
                }
            }
            else
            {
                curLen = 0;
                curStart = -1;
            }
        }
        if (bestLen > 1)
        {
            var bestEnd = bestStart + bestLen;
            if (bestEnd == hextets.Count)
            {
                hextets.Add("");
            }
            hextets.RemoveRange(bestStart, bestLen);
            hextets.Insert(bestStart, "");
            if (bestStart == 0)
            {
                hextets.Insert(0, "");
            }
        }
        return string.Join(':', hextets);
    }

    // ------------------------------------------------------------------ special ranges (Python 3.11.0)

    private static readonly (int Family, string Net)[] PrivateNets =
    [
        (4, "0.0.0.0/8"), (4, "10.0.0.0/8"), (4, "127.0.0.0/8"), (4, "169.254.0.0/16"),
        (4, "172.16.0.0/12"), (4, "192.0.0.0/29"), (4, "192.0.0.170/31"), (4, "192.0.2.0/24"),
        (4, "192.168.0.0/16"), (4, "198.18.0.0/15"), (4, "198.51.100.0/24"), (4, "203.0.113.0/24"),
        (4, "240.0.0.0/4"), (4, "255.255.255.255/32"),
        (6, "::1/128"), (6, "::/128"), (6, "::ffff:0:0/96"), (6, "100::/64"), (6, "2001::/23"),
        (6, "2001:2::/48"), (6, "2001:db8::/32"), (6, "2001:10::/28"), (6, "fc00::/7"), (6, "fe80::/10"),
    ];

    private static readonly Lazy<IpNet[]> PrivateParsed = new(() =>
        PrivateNets.Select(p => TryParseNetwork(p.Net, out var n) ? n : throw new InvalidOperationException(p.Net)).ToArray());

    public static bool Contains(IpNet net, IpAddr a) =>
        net.Family == a.Family && a.Value >= net.Network && a.Value <= net.Broadcast;

    public static bool IsPrivate(IpAddr a)
    {
        if (a.Family == 6 && (a.Value >> 32) == 0xFFFF)
        {
            return IsPrivate(new IpAddr(4, a.Value & Max4));
        }
        return PrivateParsed.Value.Any(n => Contains(n, a));
    }

    public static bool IsLoopback(IpAddr a) =>
        a.Family == 4 ? (a.Value >> 24) == 127 : a.Value == 1;

    public static bool IsLinkLocal(IpAddr a) =>
        a.Family == 4 ? (a.Value >> 16) == 0xA9FE : (a.Value >> 118) == 0x3FA;

    /// <summary>IPv4Network.is_private: both ends private.</summary>
    public static bool IsPrivate(IpNet n) =>
        IsPrivate(new IpAddr(n.Family, n.Network)) && IsPrivate(new IpAddr(n.Family, n.Broadcast));

    /// <summary><c>ipaddress.summarize_address_range(first, last)</c>.</summary>
    public static List<IpNet> Summarize(int family, BigInteger first, BigInteger last)
    {
        var bits = family == 4 ? 32 : 128;
        var allOnes = MaxOf(family);
        var nets = new List<IpNet>();
        while (first <= last)
        {
            var nbits = Math.Min(RightZeroBits(first, bits), BitLength(last - first + 1) - 1);
            nets.Add(new IpNet(family, first, bits - nbits));
            first += BigInteger.One << nbits;
            if (first - 1 == allOnes)
            {
                break;
            }
        }
        return nets;
    }
}
