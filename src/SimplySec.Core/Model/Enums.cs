using SimplySec.Core.Compat;

namespace SimplySec.Core.Model;

public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

[Flags]
public enum Profile
{
    None = 0,
    Domain = 1,
    Private = 2,
    Public = 4,
}

public enum Verdict
{
    LocalOnly,
    Blocked,
    Reachable,
    Uncertain,
}

public enum Scope
{
    None = 0,
    Specific = 1,
    LocalSubnet = 2,
    Anyone = 3,
}

public enum InterfaceKind
{
    Ethernet,
    Wifi,
    Vpn,
    Virtual,
    Loopback,
    Other,
}

public enum FindingStatus
{
    Open,
    Accepted,
    Managed,
    Info,
}

public static class EnumText
{
    public const int AllProfilesMask = 0x7FFFFFFF;
    public static readonly Profile[] SingleProfiles = [Profile.Domain, Profile.Private, Profile.Public];

    // Severity ------------------------------------------------------------
    public static string Key(this Severity s) => s switch
    {
        Severity.Info => "info",
        Severity.Low => "low",
        Severity.Medium => "medium",
        Severity.High => "high",
        Severity.Critical => "critical",
        _ => throw new ArgumentOutOfRangeException(nameof(s)),
    };

    public static string Label(this Severity s) => PyStr.Title(s.Key());

    public static Severity Shifted(this Severity s, int delta) =>
        (Severity)Math.Max((int)Severity.Info, Math.Min((int)Severity.Critical, (int)s + delta));

    public static Severity ParseSeverity(string value) => PyStr.Upper(PyStr.Strip(value)) switch
    {
        "INFO" => Severity.Info,
        "LOW" => Severity.Low,
        "MEDIUM" => Severity.Medium,
        "HIGH" => Severity.High,
        "CRITICAL" => Severity.Critical,
        _ => throw new KeyNotFoundException(value),
    };

    public static Severity Max(Severity a, Severity b) => (int)a >= (int)b ? a : b;
    public static Severity Min(Severity a, Severity b) => (int)a <= (int)b ? a : b;

    // Profile -------------------------------------------------------------
    public static string Label(this Profile p)
    {
        var names = new List<string>();
        foreach (var s in SingleProfiles)
        {
            if ((p & s) != 0)
            {
                names.Add(PyStr.Title(s.ToString().ToUpperInvariant()));
            }
        }
        return names.Count > 0 ? string.Join(" + ", names) : "None";
    }

    // Verdict -------------------------------------------------------------
    public static string Value(this Verdict v) => v switch
    {
        Verdict.LocalOnly => "local_only",
        Verdict.Blocked => "blocked",
        Verdict.Reachable => "reachable",
        Verdict.Uncertain => "uncertain",
        _ => throw new ArgumentOutOfRangeException(nameof(v)),
    };

    public static string Label(this Verdict v) => v switch
    {
        Verdict.LocalOnly => "Only this PC",
        Verdict.Blocked => "Blocked",
        Verdict.Reachable => "Reachable",
        Verdict.Uncertain => "Uncertain",
        _ => throw new ArgumentOutOfRangeException(nameof(v)),
    };

    public static Verdict ParseVerdict(string s) => s switch
    {
        "local_only" => Verdict.LocalOnly,
        "blocked" => Verdict.Blocked,
        "reachable" => Verdict.Reachable,
        "uncertain" => Verdict.Uncertain,
        _ => throw new ArgumentException(s),
    };

    // Scope ---------------------------------------------------------------
    public static string Value(this Scope s) => s switch
    {
        Scope.None => "none",
        Scope.Specific => "specific",
        Scope.LocalSubnet => "local_subnet",
        Scope.Anyone => "anyone",
        _ => throw new ArgumentOutOfRangeException(nameof(s)),
    };

    public static int Rank(this Scope s) => (int)s;

    public static Scope ParseScope(string s) => s switch
    {
        "none" => Scope.None,
        "specific" => Scope.Specific,
        "local_subnet" => Scope.LocalSubnet,
        "anyone" => Scope.Anyone,
        _ => throw new ArgumentException(s),
    };

    /// <summary>max(a, b, key=rank): the first wins on ties.</summary>
    public static Scope MaxRank(Scope a, Scope b) => b.Rank() > a.Rank() ? b : a;

    // InterfaceKind -------------------------------------------------------
    public static string Value(this InterfaceKind k) => k switch
    {
        InterfaceKind.Ethernet => "ethernet",
        InterfaceKind.Wifi => "wifi",
        InterfaceKind.Vpn => "vpn",
        InterfaceKind.Virtual => "virtual",
        InterfaceKind.Loopback => "loopback",
        InterfaceKind.Other => "other",
        _ => throw new ArgumentOutOfRangeException(nameof(k)),
    };

    public static InterfaceKind ParseKind(string s) => s switch
    {
        "ethernet" => InterfaceKind.Ethernet,
        "wifi" => InterfaceKind.Wifi,
        "vpn" => InterfaceKind.Vpn,
        "virtual" => InterfaceKind.Virtual,
        "loopback" => InterfaceKind.Loopback,
        "other" => InterfaceKind.Other,
        _ => throw new ArgumentException(s),
    };

    // FindingStatus -------------------------------------------------------
    public static string Value(this FindingStatus s) => s switch
    {
        FindingStatus.Open => "open",
        FindingStatus.Accepted => "accepted",
        FindingStatus.Managed => "managed",
        FindingStatus.Info => "info",
        _ => throw new ArgumentOutOfRangeException(nameof(s)),
    };

    public static FindingStatus ParseStatus(string s) => s switch
    {
        "open" => FindingStatus.Open,
        "accepted" => FindingStatus.Accepted,
        "managed" => FindingStatus.Managed,
        "info" => FindingStatus.Info,
        _ => throw new ArgumentException(s),
    };
}
