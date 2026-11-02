using SimplySec.Core.Model;

namespace SimplySec.Core;

/// <summary>Risk weighting for exposures, and the overall risk score and grade.</summary>
public static class Scoring
{
    public static readonly IReadOnlyDictionary<Severity, int> Weights = new Dictionary<Severity, int>
    {
        [Severity.Critical] = 25,
        [Severity.High] = 12,
        [Severity.Medium] = 5,
        [Severity.Low] = 2,
        [Severity.Info] = 0,
    };

    // How widely something is reachable. A "Keep" decision remembers its width.
    public const int WidthNone = 0;
    public const int WidthVpn = 1;
    public const int WidthPrivateSubnet = 2;
    public const int WidthPrivateAny = 3;
    public const int WidthPublicSubnet = 4;
    public const int WidthPublicAny = 5;
    public const int WidthEdge = 6;

    public static readonly IReadOnlyDictionary<int, string> WidthLabels = new Dictionary<int, string>
    {
        [WidthNone] = "nobody",
        [WidthVpn] = "your VPN or virtual machines only",
        [WidthPrivateSubnet] = "devices on your home (Private) network",
        [WidthPrivateAny] = "anyone who can reach your home (Private) network",
        [WidthPublicSubnet] = "devices on a Public network",
        [WidthPublicAny] = "anyone on a Public network",
        [WidthEdge] = "the internet (edge traversal)",
    };

    public static int ExposureWidth(IEnumerable<Exposure> exposures)
    {
        var width = WidthNone;
        foreach (var exp in exposures)
        {
            foreach (var ie in exp.PerInterface)
            {
                if (ie.Verdict != Verdict.Reachable)
                {
                    continue;
                }
                int w;
                if (ie.EdgeTraversal)
                {
                    w = WidthEdge;
                }
                else if (ie.InterfaceKind is InterfaceKind.Vpn or InterfaceKind.Virtual)
                {
                    w = WidthVpn;
                }
                else if (ie.Profile == Profile.Public)
                {
                    w = ie.Scope == Scope.Anyone ? WidthPublicAny : WidthPublicSubnet;
                }
                else
                {
                    w = ie.Scope == Scope.Anyone ? WidthPrivateAny : WidthPrivateSubnet;
                }
                width = Math.Max(width, w);
            }
        }
        return width;
    }

    /// <summary>
    /// Start from the knowledge-base risk (defined for Public exposure) and weight it: Private one
    /// level lower, VPN/virtual two lower, edge traversal one higher; unsigned and user-writable raise it.
    /// </summary>
    public static Severity ExposureSeverity(Severity baseRisk, int width, bool unsigned = false, bool userWritable = false, bool userConfigured = false)
    {
        if (width == WidthNone || baseRisk == Severity.Info)
        {
            return Severity.Info;
        }
        Severity sev;
        if (width is WidthPublicAny or WidthPublicSubnet)
        {
            sev = baseRisk;
        }
        else if (width == WidthEdge)
        {
            sev = baseRisk.Shifted(+1);
        }
        else if (width == WidthVpn)
        {
            sev = baseRisk.Shifted(-2);
        }
        else
        {
            sev = baseRisk.Shifted(-1);
        }
        var raiseBy = (unsigned ? 1 : 0) + (userWritable ? 1 : 0);
        if (raiseBy != 0)
        {
            sev = sev.Shifted(sev >= Severity.High ? Math.Min(raiseBy, 1) : raiseBy);
            sev = EnumText.Max(sev, Severity.Low);
        }
        if (userConfigured)
        {
            var cap = width >= WidthPublicSubnet ? Severity.Low : Severity.Info;
            sev = EnumText.Min(sev, cap);
        }
        return sev;
    }

    /// <summary>Risk score: 0 means nothing open, higher means riskier (capped at 100).</summary>
    public static int Score(IEnumerable<Finding> findings) =>
        Math.Min(100, findings.Where(f => f.Scored).Sum(f => Weights[f.Severity]));

    private static readonly (int Limit, string Letter)[] Bands = [(9, "A"), (19, "B"), (34, "C"), (54, "D"), (74, "E")];

    /// <summary>A is the lowest risk; a Critical finding makes it at least D and a High one at least C.</summary>
    public static string Grade(int value, IEnumerable<Finding>? findings = null)
    {
        var letter = Bands.FirstOrDefault(b => value <= b.Limit).Letter ?? "F";
        var worst = (findings ?? []).Where(f => f.Scored).Select(f => f.Severity).DefaultIfEmpty(Severity.Info).Max();
        var floor = worst == Severity.Critical ? "D" : worst == Severity.High ? "C" : "A";
        return string.CompareOrdinal(letter, floor) >= 0 ? letter : floor;
    }
}
