using System.Text.Json.Nodes;
using SimplySec.Core.Compat;
using SimplySec.Core.Model;
using static SimplySec.Core.Checks.CheckHelpers;

namespace SimplySec.Core.Checks;

/// <summary>Remote Desktop, Network Level Authentication and Remote Assistance.</summary>
public static class RemoteAccessCheck
{
    public const string CheckId = "rdp";
    public const string Area = "Remote access";

    public const string Ts = @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server";
    public const string RdpTcp = @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
    public const string Ra = @"HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance";

    public static readonly FixDef FixDisable = new()
    {
        Id = "rdp.disable",
        Label = "Turn Remote Desktop off",
        Description = "Sets fDenyTSConnections = 1 so this PC no longer accepts Remote Desktop logins.",
        MightBreak = "You (or IT support) can no longer connect to this PC with Remote Desktop.",
        Build = _ => [RegAction(Ts, "fDenyTSConnections", 1, "REG_DWORD", "Turn off Remote Desktop (fDenyTSConnections = 1).")],
        Disruptive = true,
    };

    public static readonly FixDef FixNla = new()
    {
        Id = "rdp.require_nla",
        Label = "Require Network Level Authentication",
        Description = "Sets UserAuthentication = 1 so people must sign in before a Remote Desktop session starts.",
        MightBreak = "Very old Remote Desktop clients (Windows XP era) can no longer connect.",
        Build = _ => [RegAction(RdpTcp, "UserAuthentication", 1, "REG_DWORD", "Require Network Level Authentication for Remote Desktop (UserAuthentication = 1).")],
        Recommended = true,
    };

    public static readonly FixDef FixRa = new()
    {
        Id = "rdp.remote_assistance_off",
        Label = "Turn Remote Assistance off",
        Description = "Sets fAllowToGetHelp = 0 so this PC no longer accepts Remote Assistance invitations.",
        MightBreak = "Someone helping you via Windows Remote Assistance (not Quick Assist) can no longer connect.",
        Build = _ => [RegAction(Ra, "fAllowToGetHelp", 0, "REG_DWORD", "Turn off Remote Assistance (fAllowToGetHelp = 0).")],
        Recommended = true,
    };

    public static List<Finding> Run(ScanContext ctx)
    {
        var rdp = ctx.Facts.Get("rdp");
        if (rdp is null)
        {
            var f0 = FactUnavailable(ctx, "rdp", CheckId, Area, "Remote Desktop settings");
            return f0 is null ? [] : [f0];
        }
        var output = new List<Finding>();
        var deny = !Js.IsNull(Js.Get(rdp, "deny_policy")) ? Js.Get(rdp, "deny_policy") : Js.Get(rdp, "deny");
        var enabled = Js.NumEquals(deny, 0);
        var policyRdp = !Js.IsNull(Js.Get(rdp, "deny_policy"));
        var portNode = Js.Get(rdp, "port");
        var port = Js.Truthy(portNode) ? Js.Int(portNode) : 3389;
        var groups = ctx.Groups.Where(g => g.Protocol == "tcp" && g.Port == port).ToList();
        var exposures = groups.SelectMany(g => g.Exposures).ToList();
        var reachable = exposures.Any(e => e.Verdict == Verdict.Reachable);

        if (enabled)
        {
            var width = Scoring.ExposureWidth(exposures);
            Severity sev;
            string title, what;
            if (reachable)
            {
                sev = Scoring.ExposureSeverity(Severity.High, width);
                title = $"Remote Desktop is on and can be reached by {Scoring.WidthLabels[width]}";
                what = "Anyone who can reach this PC can try to log in with Remote Desktop. It is one of the most attacked services; keep it off unless you use it.";
            }
            else
            {
                sev = Severity.Low;
                title = "Remote Desktop is on (currently blocked by the firewall)";
                what = "Remote Desktop accepts logins, but the firewall stops other devices reaching it right now.";
            }
            var fixes = new List<FixOption> { FixDisable.Option() };
            if (reachable)
            {
                var opt = ctx.FixOption("exposure.block_port_public",
                    new JsonObject { ["protocol"] = "tcp", ["port"] = port, ["label"] = "Remote Desktop" });
                if (opt is not null && width >= Scoring.WidthPublicSubnet)
                {
                    fixes.Add(opt);
                }
            }
            var details = new List<(string, string)> { ("fDenyTSConnections", S(deny)), ("Port", port.ToString(System.Globalization.CultureInfo.InvariantCulture)) };
            details.AddRange(exposures.SelectMany(e => e.PerInterface).Select(ie => ($"via {ie.Interface}", ie.Reason)));
            var f = NewFinding("rdp.enabled", CheckId, Area, title, sev, what, details, fixes);
            if (policyRdp)
            {
                f.Status = FindingStatus.Managed;
            }
            output.Add(f);

            var nla = !Js.IsNull(Js.Get(rdp, "nla_policy")) ? Js.Get(rdp, "nla_policy") : Js.Get(rdp, "nla");
            if (Js.NumEquals(nla, 0))
            {
                var fn = NewFinding("rdp.nla_off", CheckId, Area,
                    "Remote Desktop does not require sign-in first (NLA is off)", Severity.High,
                    "Without Network Level Authentication, anyone can open a login screen on this PC and attackers can exploit Remote Desktop bugs before signing in.",
                    [("UserAuthentication", S(nla))], [FixNla.Option()]);
                if (!Js.IsNull(Js.Get(rdp, "nla_policy")))
                {
                    fn.Status = FindingStatus.Managed;
                }
                output.Add(fn);
            }
        }

        var ra = Js.Get(rdp, "remote_assistance_policy");
        var raPolicy = !Js.IsNull(ra);
        if (Js.IsNull(ra))
        {
            ra = Js.Get(rdp, "remote_assistance");
        }
        if (Js.NumEquals(ra, 1))
        {
            var f = NewFinding("rdp.remote_assistance_on", CheckId, Area, "Remote Assistance is on", Severity.Low,
                "Remote Assistance lets someone you send an invitation to see and control your screen. Scammers often talk people into this. Quick Assist still works if you turn it off.",
                [("fAllowToGetHelp", "1")], [FixRa.Option()]);
            if (raPolicy)
            {
                f.Status = FindingStatus.Managed;
            }
            output.Add(f);
        }
        return output;
    }

    public static readonly Check Definition = new()
    {
        Id = CheckId,
        Area = Area,
        Run = Run,
        Fixes = [FixDisable, FixNla, FixRa],
        Allows = [RegAllow((Ts, "fDenyTSConnections"), (RdpTcp, "UserAuthentication"), (Ra, "fAllowToGetHelp"))],
    };
}

/// <summary>Legacy protocols: SMBv1, LLMNR and NetBIOS over TCP/IP.</summary>
public static class LegacyCheck
{
    public const string Area = "Legacy protocols";
    public const string DnsClient = @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";

    public static readonly FixDef FixSmb1 = new()
    {
        Id = "legacy.smb1_off",
        Label = "Turn SMBv1 off",
        Description = "Turns off the 30-year-old SMB version 1 file-sharing server, used by the WannaCry worm.",
        MightBreak = "Only very old devices (Windows XP, some old NAS boxes and scanners) used SMBv1 to reach this PC.",
        Build = _ => [new ActionSpec("smb.server_setting", new JsonObject { ["smb1"] = false },
            "Turn off the SMBv1 file-sharing server (Set-SmbServerConfiguration -EnableSMB1Protocol $false).")],
        Recommended = true,
    };

    public static readonly FixDef FixLlmnr = new()
    {
        Id = "legacy.llmnr_off",
        Label = "Turn LLMNR off",
        Description = "Sets the DNS Client policy EnableMulticast = 0 so Windows stops answering and sending LLMNR lookups.",
        MightBreak = "Finding very old PCs by name without DNS may stop working; mDNS and DNS keep working.",
        Build = _ => [RegAction(DnsClient, "EnableMulticast", 0, "REG_DWORD", "Turn off LLMNR (DNSClient policy EnableMulticast = 0).")],
        Disruptive = true,
    };

    public static readonly FixDef FixNetbios = new()
    {
        Id = "legacy.netbios_off",
        Label = "Turn NetBIOS off",
        Description = "Turns off NetBIOS over TCP/IP on each network adapter where it is on.",
        MightBreak = "Very old devices that find PCs by NetBIOS name (old printers, NAS boxes, Windows XP) may not see this PC.",
        Build = BuildNetbios,
        Disruptive = true,
        ParamsFrom = ctx =>
        {
            var adapters = NetbiosOn(ctx);
            return adapters.Count > 0 ? new JsonObject { ["adapters"] = new JsonArray(adapters.ToArray<JsonNode?>()) } : null;
        },
    };

    private static List<ActionSpec> BuildNetbios(JsonObject p)
    {
        var output = new List<ActionSpec>();
        foreach (var a in Js.Get(p, "adapters") as JsonArray ?? [])
        {
            var ci = Js.Get(a, "config_index");
            output.Add(new ActionSpec("netbios.adapter",
                new JsonObject
                {
                    ["config_index"] = Js.Int(ci),
                    ["description"] = Js.Clone(GetOr(a, "description", JsonValue.Create(""))),
                    ["option"] = 2,
                },
                $"Turn off NetBIOS over TCP/IP on '{S(GetOr(a, "description", ci))}'."));
        }
        return output;
    }

    internal static List<JsonObject> NetbiosOn(ScanContext ctx)
    {
        var net = ctx.Facts.GetOrEmpty("network");
        var output = new List<JsonObject>();
        foreach (var c in Js.AsList(Js.Get(net, "config")))
        {
            var nb = Js.Get(c, "netbios");
            if (Js.NumEquals(nb, 0) || Js.NumEquals(nb, 1))
            {
                output.Add(new JsonObject
                {
                    ["config_index"] = Js.Clone(Js.Get(c, "config_index")),
                    ["description"] = Js.Clone(GetOr(c, "description", JsonValue.Create(""))),
                    ["index"] = Js.Clone(Js.Get(c, "index")),
                    ["setting"] = Js.Clone(nb),
                });
            }
        }
        return output;
    }

    private static bool OnPublic(ScanContext ctx) =>
        ctx.ActiveInterfaces().Any(i => i.Profile == Profile.Public && i.Kind is InterfaceKind.Ethernet or InterfaceKind.Wifi);

    public static List<Finding> Run(ScanContext ctx)
    {
        var output = new List<Finding>();
        var smb = ctx.Facts.Get("smb");
        if (smb is null)
        {
            var f = FactUnavailable(ctx, "smb", "legacy", Area, "the SMB file-sharing settings");
            if (f is not null)
            {
                output.Add(f);
            }
        }
        else if (Js.Truthy(Js.Get(smb, "smb1")))
        {
            output.Add(NewFinding("legacy.smb1_on", "legacy", Area, "The old SMBv1 file-sharing server is on", Severity.High,
                "SMB version 1 is the protocol the WannaCry and NotPetya worms spread through. Modern devices use SMB 2 or 3.",
                [("EnableSMB1Protocol", "True")], [FixSmb1.Option()]));
        }

        var llmnr = ctx.Facts.Get("llmnr");
        if (llmnr is not null && !Js.NumEquals(Js.Get(llmnr, "enable_multicast_policy"), 0))
        {
            var pub = OnPublic(ctx);
            output.Add(NewFinding("legacy.llmnr_on", "legacy", Area, "LLMNR name lookups are on (optional fix)",
                pub ? Severity.Medium : Severity.Low,
                "When a name can't be found in DNS, Windows shouts the question to the whole network. An attacker on the same network can answer, pretend to be that PC and capture your password hash. Risky on public Wi-Fi.",
                [("DNSClient EnableMulticast policy", S(Js.Get(llmnr, "enable_multicast_policy")))],
                [FixLlmnr.Option()],
                "Turning it off rarely affects home networks; very old devices may need it."));
        }

        var adapters = NetbiosOn(ctx);
        if (adapters.Count > 0)
        {
            var pub = OnPublic(ctx);
            output.Add(NewFinding("legacy.netbios_on", "legacy", Area,
                $"NetBIOS is on for {adapters.Count} network adapter(s) (optional fix)",
                pub ? Severity.Medium : Severity.Low,
                "NetBIOS is an old way for Windows PCs to find each other. Like LLMNR it can be abused on the same network to capture password hashes, and it reveals this PC's name.",
                adapters.Select(a => (
                    Js.Truthy(a["description"]) ? S(a["description"]) : $"Adapter {S(a["config_index"])}",
                    Js.NumEquals(a["setting"], 0) ? "default (from DHCP)" : "on")).ToList(),
                [FixNetbios.Option(new JsonObject { ["adapters"] = new JsonArray(adapters.Select(a => (JsonNode?)a.DeepClone()).ToArray()) })]));
        }
        return output;
    }

    public static readonly Check Definition = new()
    {
        Id = "legacy",
        Area = Area,
        Run = Run,
        Fixes = [FixSmb1, FixLlmnr, FixNetbios],
        Allows =
        [
            RegAllow((DnsClient, "EnableMulticast")),
            new Allow("smb.server_setting", p => p.Count == 1 && p.ContainsKey("smb1") && Js.IsBool(p["smb1"])),
            new Allow("netbios.adapter", p => Js.IsInt(Js.Get(p, "config_index"))
                && (Js.NumEquals(Js.Get(p, "option"), 0) || Js.NumEquals(Js.Get(p, "option"), 1) || Js.NumEquals(Js.Get(p, "option"), 2))),
        ],
    };
}
