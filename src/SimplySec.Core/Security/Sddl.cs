using System.Text.RegularExpressions;
using SimplySec.Core.Compat;

namespace SimplySec.Core.Security;

/// <summary>Allow/deny SIDs of a firewall rule's local-user condition.</summary>
public sealed class UserCondition
{
    public HashSet<string> Allow { get; } = new(StringComparer.Ordinal);
    public HashSet<string> Deny { get; } = new(StringComparer.Ordinal);

    private static readonly HashSet<string> EveryoneLike = new(StringComparer.Ordinal) { "S-1-1-0", "S-1-5-11" };

    /// <summary>True: applies to this user; false: does not; null: cannot tell.</summary>
    public bool? Decide(string? userSid)
    {
        var groupsInvolved = Allow.Concat(Deny).Any(s =>
            s.StartsWith("S-1-5-32-", StringComparison.Ordinal) || s is "S-1-5-4" or "S-1-15-2-1");
        if (userSid is null)
        {
            return null;
        }
        var sid = PyStr.Upper(userSid);
        if (Deny.Contains(sid))
        {
            return false;
        }
        if (Allow.Contains(sid) || Allow.Overlaps(EveryoneLike))
        {
            return true;
        }
        // Group SIDs (Administrators, Users, Interactive) need token group membership.
        return groupsInvolved ? null : false;
    }
}

/// <summary>Minimal SDDL reader for firewall rule user conditions.</summary>
public static partial class Sddl
{
    public static readonly IReadOnlyDictionary<string, string> Aliases = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["WD"] = "S-1-1-0",
        ["AU"] = "S-1-5-11",
        ["IU"] = "S-1-5-4",
        ["SY"] = "S-1-5-18",
        ["LS"] = "S-1-5-19",
        ["NS"] = "S-1-5-20",
        ["BA"] = "S-1-5-32-544",
        ["BU"] = "S-1-5-32-545",
        ["BG"] = "S-1-5-32-546",
        ["AC"] = "S-1-15-2-1",
    };

    [GeneratedRegex(@"\(([^)]*)\)")]
    private static partial Regex Ace();

    public static UserCondition ParseUserCondition(string sddl)
    {
        var cond = new UserCondition();
        var at = sddl.IndexOf("D:", StringComparison.Ordinal);
        var dacl = at >= 0 ? sddl[(at + 2)..] : sddl;
        foreach (Match m in Ace().Matches(dacl))
        {
            var parts = m.Groups[1].Value.Split(';');
            if (parts.Length < 6)
            {
                continue;
            }
            var aceType = PyStr.Upper(parts[0]);
            var sid = PyStr.Upper(PyStr.Strip(parts[5]));
            sid = Aliases.TryGetValue(sid, out var full) ? full : sid;
            if (aceType == "A")
            {
                cond.Allow.Add(sid);
            }
            else if (aceType == "D")
            {
                cond.Deny.Add(sid);
            }
        }
        return cond;
    }
}
