using System.Text.Json.Nodes;
using SimplySec.Core.Compat;
using SimplySec.Core.Model;
using static SimplySec.Core.Checks.CheckHelpers;

namespace SimplySec.Core.Checks;

/// <summary>Firewall profiles: on/off and the default action for incoming connections.</summary>
public static class FirewallCheck
{
    public const string CheckId = "firewall";
    public const string Area = "Firewall";

    public static readonly FixDef FixEnable = new()
    {
        Id = "firewall.enable",
        Label = "Turn the firewall on",
        Description = "Turns Windows Defender Firewall on for this network type.",
        MightBreak = "Programs that relied on the firewall being off may ask for permission the next time they accept connections.",
        Build = p =>
        {
            var prof = (Profile)Js.Int(Js.Get(p, "profile"));
            return [new ActionSpec("firewall.profile", new JsonObject { ["profile"] = (int)prof, ["enabled"] = true },
                $"Turn the Windows firewall on for {prof.Label()} networks.")];
        },
        Recommended = true,
    };

    public static readonly FixDef FixDefaultBlock = new()
    {
        Id = "firewall.default_block",
        Label = "Block incoming connections by default",
        Description = "Only programs with an allow rule can accept connections (the Windows default).",
        MightBreak = "Programs without an allow rule stop accepting connections from other devices.",
        Build = p =>
        {
            var prof = (Profile)Js.Int(Js.Get(p, "profile"));
            return [new ActionSpec("firewall.profile", new JsonObject { ["profile"] = (int)prof, ["default_inbound_block"] = true },
                $"Set the firewall to block incoming connections by default on {prof.Label()} networks.")];
        },
        Disruptive = true,
    };

    private static bool AllowProfile(JsonObject p)
    {
        var keys = p.Select(kv => kv.Key).Where(k => k != "profile").ToHashSet(StringComparer.Ordinal);
        var profile = Js.Long(GetOr(p, "profile", JsonValue.Create(0)));
        return profile is 1 or 2 or 4
               && keys.Count > 0
               && keys.All(k => k is "enabled" or "default_inbound_block")
               && keys.All(k => Js.IsBool(p[k]));
    }

    private static string ProfileName(Profile p) => p.ToString().ToLowerInvariant();

    public static List<Finding> Run(ScanContext ctx)
    {
        var output = new List<Finding>();
        var managed = ctx.Firewall.ManagedByPolicy;
        foreach (var (prof, state) in ctx.Firewall.Profiles)
        {
            var inUse = (ctx.Firewall.CurrentProfiles & (int)prof) != 0;
            var where = inUse ? "the network you are on now" : $"{prof.Label()} networks";
            if (!state.Enabled)
            {
                var f = NewFinding(
                    $"firewall.off.{ProfileName(prof)}", CheckId, Area,
                    $"The firewall is off for {prof.Label()} networks",
                    inUse || prof == Profile.Public ? Severity.Critical : Severity.High,
                    $"Without the firewall, any device on {where} can connect to every program that listens on this PC.",
                    [("Profile", prof.Label()), ("In use now", inUse ? "yes" : "no")],
                    [FixEnable.Option(new JsonObject { ["profile"] = (int)prof })]);
                if (managed)
                {
                    f.Status = FindingStatus.Managed;
                }
                output.Add(f);
            }
            else if (!state.DefaultInboundBlock)
            {
                var f = NewFinding(
                    $"firewall.default_allow.{ProfileName(prof)}", CheckId, Area,
                    $"The firewall lets in all connections by default on {prof.Label()} networks",
                    inUse || prof == Profile.Public ? Severity.High : Severity.Medium,
                    "The firewall is on, but anything not explicitly blocked is allowed in. Windows normally blocks by default and only lets in programs you approved.",
                    [("Profile", prof.Label()), ("Default inbound action", "Allow")],
                    [FixDefaultBlock.Option(new JsonObject { ["profile"] = (int)prof })]);
                if (managed)
                {
                    f.Status = FindingStatus.Managed;
                }
                output.Add(f);
            }
        }
        return output;
    }

    public static readonly Check Definition = new()
    {
        Id = CheckId,
        Area = Area,
        Run = Run,
        Fixes = [FixEnable, FixDefaultBlock],
        Allows = [new Allow("firewall.profile", AllowProfile)],
    };
}

/// <summary>Shared folders that grant access to Everyone, anonymous users or guests (guidance only).</summary>
public static class SharingCheck
{
    public const string Area = "File sharing";

    private static readonly Dictionary<string, string> OpenSids = new(StringComparer.Ordinal)
    {
        ["S-1-1-0"] = "Everyone",
        ["S-1-5-7"] = "Anonymous",
        ["S-1-5-32-546"] = "Guests",
    };

    private static string Rights(JsonNode? right) =>
        Js.NumEquals(right, 0) ? "Full control"
        : Js.NumEquals(right, 1) ? "Change"
        : Js.NumEquals(right, 2) ? "Read"
        : Js.NumEquals(right, 3) ? "Custom"
        : "?";

    public static readonly FixDef FixGuide = new()
    {
        Id = "sharing.review",
        Label = "Open sharing settings",
        Description = "Opens Windows' advanced sharing settings so you can review who can access shared folders.",
        MightBreak = "Nothing changes until you change it yourself.",
        Guidance = "sharing",
    };

    public static List<Finding> Run(ScanContext ctx)
    {
        var shares = ctx.Facts.Get("shares");
        if (shares is null)
        {
            var f = FactUnavailable(ctx, "shares", "sharing", Area, "shared folders");
            return f is null ? [] : [f];
        }
        var output = new List<Finding>();
        foreach (var share in Js.AsList(shares))
        {
            var bad = Js.AsList(Js.Get(share, "access"))
                .Where(a => Js.Truthy(Js.Get(a, "allow")) && OpenSids.ContainsKey(PyStr.Upper(Js.Truthy(Js.Get(a, "sid")) ? S(Js.Get(a, "sid")) : "")))
                .ToList();
            if (bad.Count == 0)
            {
                continue;
            }
            var writable = bad.Any(a => Js.NumEquals(Js.Get(a, "right"), 0) || Js.NumEquals(Js.Get(a, "right"), 1));
            var who = string.Join(", ", bad.Select(a => OpenSids[PyStr.Upper(S(Js.Get(a, "sid")))]).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal));
            var name = Js.Get(share, "name");
            var details = new List<(string, string)> { ("Path", GetStr(share, "path")) };
            details.AddRange(bad.Select(a => (S(GetOr(a, "account", Js.Get(a, "sid"))), Rights(Js.Get(a, "right")))));
            output.Add(NewFinding(
                $"sharing.open.{PyStr.Lower(GetStr(share, "name"))}", "sharing", Area,
                $"Shared folder '{S(name)}' is open to {who}",
                writable ? Severity.High : Severity.Medium,
                "Anyone who can sign in to this PC over the network can " + (writable ? "change or delete" : "read") +
                " these files. Ransomware on another PC can encrypt writable shares too.",
                details, [FixGuide.Option()],
                "Share with specific user accounts instead of Everyone, and give Read access where Change isn't needed."));
        }
        return output;
    }

    public static readonly Check Definition = new() { Id = "sharing", Area = Area, Run = Run, Fixes = [FixGuide] };
}
