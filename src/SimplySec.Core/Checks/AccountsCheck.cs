using System.Text.Json.Nodes;
using SimplySec.Core.Compat;
using SimplySec.Core.Model;
using static SimplySec.Core.Checks.CheckHelpers;

namespace SimplySec.Core.Checks;

/// <summary>Accounts: UAC prompts, the Guest account, blank-password network logons.</summary>
public static class AccountsCheck
{
    public const string Area = "Accounts";
    public const string PolSys = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    public const string Lsa = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";

    public static readonly FixDef FixUac = new()
    {
        Id = "accounts.uac_prompt",
        Label = "Turn UAC prompts back on",
        Description = "Restores the Windows default: programs must ask before getting administrator rights.",
        MightBreak = "You'll see a prompt when a program needs administrator rights.",
        Build = p =>
        {
            var output = new List<ActionSpec>();
            if (Js.Truthy(Js.Get(p, "enable_lua")))
            {
                output.Add(RegAction(PolSys, "EnableLUA", 1, "REG_DWORD", "Turn User Account Control on (EnableLUA = 1, takes effect after a restart)."));
            }
            if (Js.Truthy(Js.Get(p, "consent")))
            {
                output.Add(RegAction(PolSys, "ConsentPromptBehaviorAdmin", 5, "REG_DWORD",
                    "Ask for consent before programs get administrator rights (ConsentPromptBehaviorAdmin = 5, the Windows default)."));
            }
            return output;
        },
        Recommended = true,
    };

    public static readonly FixDef FixGuest = new()
    {
        Id = "accounts.guest_off",
        Label = "Disable the Guest account",
        Description = "Disables the built-in Guest account (found by its fixed ID, RID 501).",
        MightBreak = "Nobody can sign in as Guest, locally or over the network.",
        Build = _ => [new ActionSpec("account.enabled", new JsonObject { ["rid"] = 501, ["enabled"] = false }, "Disable the built-in Guest account.")],
        Recommended = true,
    };

    public static readonly FixDef FixBlank = new()
    {
        Id = "accounts.blank_password_limit",
        Label = "Block network logons with blank passwords",
        Description = "Sets LimitBlankPasswordUse = 1 (the Windows default): accounts without a password can only sign in at the keyboard.",
        MightBreak = "Accounts with no password can't be used to open shared folders from other PCs.",
        Build = _ => [RegAction(Lsa, "LimitBlankPasswordUse", 1, "REG_DWORD", "Block network logons for accounts with blank passwords (LimitBlankPasswordUse = 1).")],
        Recommended = true,
    };

    public static List<Finding> Run(ScanContext ctx)
    {
        var output = new List<Finding>();
        var uac = ctx.Facts.Get("uac");
        if (uac is null)
        {
            var f = FactUnavailable(ctx, "uac", "accounts", Area, "User Account Control");
            if (f is not null)
            {
                output.Add(f);
            }
        }
        else
        {
            var luaOff = Js.NumEquals(Js.Get(uac, "enable_lua"), 0);
            var noPrompt = Js.NumEquals(Js.Get(uac, "consent_admin"), 0);
            if (luaOff || noPrompt)
            {
                output.Add(NewFinding("accounts.uac_off", "accounts", Area,
                    luaOff ? "User Account Control is off" : "Programs get administrator rights without asking",
                    Severity.High,
                    "User Account Control makes programs ask before they change system settings. Without it, any program you run, including malware, gets full control silently.",
                    [("EnableLUA", S(Js.Get(uac, "enable_lua"))), ("ConsentPromptBehaviorAdmin", S(Js.Get(uac, "consent_admin")))],
                    [FixUac.Option(new JsonObject { ["enable_lua"] = luaOff, ["consent"] = noPrompt })]));
            }
        }

        var acc = ctx.Facts.Get("accounts");
        if (acc is null)
        {
            var f = FactUnavailable(ctx, "accounts", "accounts", Area, "local accounts");
            if (f is not null)
            {
                output.Add(f);
            }
            return output;
        }
        var users = Js.AsList(Js.Get(acc, "users"));
        var guest = users.FirstOrDefault(u => S(GetOr(u, "sid", JsonValue.Create(""))).EndsWith("-501", StringComparison.Ordinal));
        if (Js.Truthy(guest) && Js.Truthy(Js.Get(guest, "enabled")))
        {
            output.Add(NewFinding("accounts.guest_on", "accounts", Area, "The Guest account is enabled", Severity.High,
                "The Guest account needs no password. Anyone can use it to sign in, also over the network.",
                [("Account", S(GetOr(guest, "name", JsonValue.Create("Guest"))))], [FixGuest.Option()]));
        }
        if (Js.NumEquals(Js.Get(acc, "limit_blank_password_use"), 0))
        {
            var blank = users
                .Where(u => Js.Truthy(Js.Get(u, "enabled")) && Js.IsBool(Js.Get(u, "password_required")) && !Js.Get(u, "password_required")!.GetValue<bool>())
                .Select(u => S(Js.Get(u, "name")))
                .ToList();
            var details = new List<(string, string)> { ("LimitBlankPasswordUse", "0") };
            if (blank.Count > 0)
            {
                details.Add(("Accounts without a required password", string.Join(", ", blank)));
            }
            output.Add(NewFinding("accounts.blank_passwords", "accounts", Area, "Accounts with no password can sign in over the network", Severity.High,
                "Windows normally only lets password-less accounts sign in at the keyboard. This PC allows it over the network too.",
                details, [FixBlank.Option()]));
        }
        return output;
    }

    public static readonly Check Definition = new()
    {
        Id = "accounts",
        Area = Area,
        Run = Run,
        Fixes = [FixUac, FixGuest, FixBlank],
        Allows =
        [
            RegAllow((PolSys, "EnableLUA"), (PolSys, "ConsentPromptBehaviorAdmin"), (Lsa, "LimitBlankPasswordUse")),
            new Allow("account.enabled", p => Js.NumEquals(Js.Get(p, "rid"), 501) && Js.IsBool(Js.Get(p, "enabled")) && !p["enabled"]!.GetValue<bool>()),
        ],
    };
}

/// <summary>System hardening: AutoRun and BitLocker drive encryption.</summary>
public static class SystemCheck
{
    public const string Area = "System";
    public const string Explorer = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    private static readonly HashSet<long> LaptopChassis = [8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32];

    private static readonly Dictionary<long, string> BitlockerStates = new()
    {
        [1] = "on",
        [2] = "off",
        [3] = "encrypting",
        [4] = "decrypting",
        [5] = "suspended",
        [6] = "on (locked)",
        [8] = "waiting for activation",
    };

    public static readonly FixDef FixAutorun = new()
    {
        Id = "system.autorun_off",
        Label = "Turn AutoRun off for all drives",
        Description = "Sets NoDriveTypeAutoRun = 255 so USB sticks and discs can't start programs automatically.",
        MightBreak = "Discs and USB sticks no longer start their installers by themselves; open them in File Explorer instead.",
        Build = _ => [RegAction(Explorer, "NoDriveTypeAutoRun", 255, "REG_DWORD", "Turn off AutoRun for all drive types (NoDriveTypeAutoRun = 255).")],
    };

    public static readonly FixDef FixBitlocker = new()
    {
        Id = "system.bitlocker_guide",
        Label = "Open device encryption settings",
        Description = "Opens Settings so you can turn on BitLocker / device encryption. Save the recovery key somewhere safe first.",
        MightBreak = "Nothing changes until you turn encryption on.",
        Guidance = "bitlocker",
    };

    public static List<Finding> Run(ScanContext ctx)
    {
        var output = new List<Finding>();
        var autorun = ctx.Facts.Get("autorun");
        if (autorun is not null
            && !Js.NumEquals(Js.Get(autorun, "hklm"), 255)
            && !Js.NumEquals(Js.Get(autorun, "hkcu"), 255)
            && !Js.NumEquals(Js.Get(autorun, "no_autorun_hklm"), 1))
        {
            output.Add(NewFinding("system.autorun", "system", Area, "AutoRun is not fully turned off", Severity.Low,
                "AutoRun lets a disc or USB drive start a program when inserted. Modern Windows limits it, but the recommended setting turns it off for every drive type.",
                [("NoDriveTypeAutoRun (HKLM)", S(Js.Get(autorun, "hklm")))], [FixAutorun.Option()]));
        }

        var bl = ctx.Facts.Get("bitlocker");
        if (bl is null)
        {
            var f = FactUnavailable(ctx, "bitlocker", "system", Area, "drive encryption");
            if (f is not null)
            {
                output.Add(f);
            }
            return output;
        }
        var state = Js.Get(bl, "protection");
        var system = ctx.Facts.GetOrEmpty("system");
        var chassis = Js.Truthy(Js.Get(system, "chassis")) ? Js.AsList(Js.Get(system, "chassis")) : [];
        var laptop = Js.Truthy(Js.Get(system, "has_battery")) || chassis.Any(c => Js.IsNumber(c) && LaptopChassis.Contains(Js.Long(c)));
        if (Js.NumEquals(state, 2) || Js.NumEquals(state, 5) || Js.NumEquals(state, 8))
        {
            var sev = laptop ? Severity.High : Severity.Low;
            var stateKey = Js.Long(state);
            output.Add(NewFinding("system.bitlocker_off", "system", Area,
                $"Drive {S(GetOr(bl, "drive", JsonValue.Create("C:")))} is not encrypted" + (Js.NumEquals(state, 5) ? " (protection suspended)" : ""),
                sev,
                "If this PC is lost or stolen, anyone can read its files by removing the drive. " +
                (laptop ? "Laptops are lost far more often, so this matters more here." : "On a desktop at home this is less urgent."),
                [("BitLocker", BitlockerStates.TryGetValue(stateKey, out var label) ? label : S(state)), ("Device", laptop ? "laptop" : "desktop")],
                [FixBitlocker.Option()],
                "BitLocker needs Windows Pro; Windows Home offers 'Device encryption' on supported hardware."));
        }
        return output;
    }

    public static readonly Check Definition = new()
    {
        Id = "system",
        Area = Area,
        Run = Run,
        Fixes = [FixAutorun, FixBitlocker],
        Allows = [RegAllow((Explorer, "NoDriveTypeAutoRun"))],
    };
}

/// <summary>Wi-Fi on this PC: weak saved networks that connect automatically, and open networks now.</summary>
public static class WifiCheck
{
    public const string Area = "Wi-Fi";

    public static readonly FixDef FixManual = new()
    {
        Id = "wifi.manual_connect",
        Label = "Stop auto-connecting",
        Description = "Windows will only join these networks when you pick them yourself. The saved networks stay.",
        MightBreak = "You'll have to choose these networks by hand when you want to use them.",
        Build = p => (Js.Get(p, "profiles") as JsonArray ?? [])
            .Select(n => new ActionSpec("wifi.connection_mode", new JsonObject { ["profile_name"] = Js.Clone(n), ["mode"] = "manual" },
                $"Stop connecting to the Wi-Fi network '{S(n)}' automatically (connection mode: manual)."))
            .ToList(),
    };

    public static readonly FixDef FixGuide = new()
    {
        Id = "wifi.open_settings",
        Label = "Open network settings",
        Description = "Opens Settings so you can disconnect or use a VPN.",
        MightBreak = "Nothing changes until you change it yourself.",
        Guidance = "network",
    };

    public static List<Finding> Run(ScanContext ctx)
    {
        var profiles = ctx.Facts.Get("wifi");
        if (profiles is null)
        {
            return [];
        }
        var output = new List<Finding>();
        var weak = Js.AsList(profiles).Where(p => Js.Truthy(Js.Get(p, "weak"))).ToList();
        var auto = weak.Where(p => Js.PyEquals(Js.Get(p, "connection_mode"), JsonValue.Create("auto"))).ToList();
        if (auto.Count > 0)
        {
            output.Add(NewFinding("wifi.weak_autoconnect", "wifi", Area,
                $"This PC joins {auto.Count} insecure Wi-Fi network(s) automatically", Severity.Medium,
                "Anyone can create a Wi-Fi network with the same name as an open or weakly protected one you used before. Your PC would join it automatically, letting them watch or redirect your traffic.",
                auto.Select(p => (S(p!["name"]), S(p["weak"]))).ToList(),
                [FixManual.Option(new JsonObject { ["profiles"] = new JsonArray(auto.Select(p => Js.Clone(p!["name"])).ToArray()) })]));
        }
        var connected = ctx.ActiveInterfaces()
            .Where(i => i.Kind == InterfaceKind.Wifi && i.NetworkName.Length > 0)
            .Select(i => i.NetworkName).ToHashSet(StringComparer.Ordinal);
        bool In(JsonNode? n) => Js.IsString(n) && connected.Contains(n!.GetValue<string>());
        foreach (var p in weak.Where(p => In(Js.Get(p, "ssid")) || In(Js.Get(p, "name"))))
        {
            output.Add(NewFinding($"wifi.connected_insecure.{S(p!["name"])}", "wifi", Area,
                $"You are connected to an insecure Wi-Fi network: {S(p["name"])}", Severity.High,
                $"This network is {S(p["weak"])}. Others nearby can see unencrypted traffic and may pretend to be websites. Avoid signing in to anything important, or use a VPN.",
                fixes: [FixGuide.Option()]));
        }
        return output;
    }

    public static readonly Check Definition = new()
    {
        Id = "wifi",
        Area = Area,
        Run = Run,
        Fixes = [FixManual, FixGuide],
        Allows =
        [
            new Allow("wifi.connection_mode", p => Js.IsString(Js.Get(p, "profile_name"))
                && (Js.PyEquals(Js.Get(p, "mode"), JsonValue.Create("manual")) || Js.PyEquals(Js.Get(p, "mode"), JsonValue.Create("auto")))),
        ],
    };
}

/// <summary>Housekeeping: SimplySec v1 leftovers, managed (organisation) PCs, network categories.</summary>
public static class HousekeepingCheck
{
    public const string Area = "Housekeeping";

    public static readonly string[] V1Patterns =
    [
        "simplesec-*",
        "*-simplesec",
        "blockport*",
        "restrictport*",
        "simplesec-winrm-*-allowlocal",
    ];

    public static bool IsV1Rule(string? name)
    {
        var n = PyStr.Lower(name);
        return V1Patterns.Any(p => PyStr.FnMatchCase(n, p));
    }

    public static readonly FixDef FixCleanup = new()
    {
        Id = "housekeeping.remove_v1_rules",
        Label = "Remove v1 leftovers",
        Description = "Removes the firewall rules the old SimpleSec v1 created. Their definitions are saved so this can be undone.",
        MightBreak = "Nothing SimplySec 2 relies on. Some v1 rules opened ports to your network; those will close.",
        Build = p => (Js.Get(p, "names") as JsonArray ?? [])
            .Select(n => new ActionSpec("firewall.remove_rule", new JsonObject { ["name"] = Js.Clone(n) },
                $"Remove old v1 firewall rule '{S(n)}' (its full definition is saved for undo)."))
            .ToList(),
    };

    public static readonly FixDef FixPrivate = new()
    {
        Id = "network.mark_private",
        Label = "Mark as Private (home) network",
        Description = "Tells Windows this is your trusted home network, so your own devices can reach this PC under the Private firewall rules.",
        MightBreak = "Only do this for your own home or office network, never for café or hotel Wi-Fi.",
        Build = p =>
        {
            var nameNode = Js.Truthy(Js.Get(p, "name")) ? Js.Get(p, "name") : Js.Get(p, "alias");
            return
            [
                new ActionSpec("network.category",
                    new JsonObject
                    {
                        ["index"] = Js.Int(p["index"]),
                        ["alias"] = Js.Clone(GetOr(p, "alias", JsonValue.Create(""))),
                        ["profile"] = "Private",
                    },
                    $"Mark the network '{S(nameNode)}' ({S(Js.Get(p, "alias"))}) as Private (a trusted home network)."),
            ];
        },
    };

    public static List<Finding> Run(ScanContext ctx)
    {
        var output = new List<Finding>();
        var leftovers = ctx.Firewall.Rules.Where(r => IsV1Rule(r.Name)).ToList();
        if (leftovers.Count > 0)
        {
            var names = leftovers.Select(r => r.Name).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();
            var allowRules = leftovers.Where(r => r.Action == "allow").ToList();
            output.Add(NewFinding("housekeeping.v1_rules", "housekeeping", Area,
                $"{names.Count} firewall rule(s) left behind by SimpleSec v1",
                allowRules.Count > 0 ? Severity.Medium : Severity.Low,
                "The old version created firewall rules in several formats and could not clean them up. " +
                (allowRules.Count > 0 ? "Some of them OPEN ports to your network. " : "") +
                "Removing them is safe and can be undone.",
                leftovers.Select(r => (r.Name, $"{r.Action} {r.ProtocolLabel} {r.LocalPorts} from {r.RemoteAddresses}")).ToList(),
                [FixCleanup.Option(new JsonObject { ["names"] = Js.StrArray(names) })]));
        }
        if (ctx.Managed)
        {
            var system = ctx.Facts.GetOrEmpty("system");
            var reason = Js.Truthy(Js.Get(system, "part_of_domain"))
                ? $"it is joined to the domain '{S(Js.Get(system, "domain"))}'"
                : "Group Policy sets its firewall";
            var f = NewFinding("housekeeping.managed", "housekeeping", Area, "This PC is managed by an organisation", Severity.Info,
                $"SimplySec detected that {reason}. Settings controlled by your organisation are reported only and never changed. Ask your IT team about them.");
            f.Status = FindingStatus.Info;
            output.Add(f);
        }
        return output;
    }

    public static readonly Check Definition = new()
    {
        Id = "housekeeping",
        Area = Area,
        Run = Run,
        Fixes = [FixCleanup, FixPrivate],
        Allows =
        [
            new Allow("firewall.remove_rule", p => p.Count == 1 && p.ContainsKey("name") && IsV1Rule(S(p["name"]))),
            new Allow("network.category", p => Js.IsInt(Js.Get(p, "index"))
                && (Js.PyEquals(Js.Get(p, "profile"), JsonValue.Create("Private")) || Js.PyEquals(Js.Get(p, "profile"), JsonValue.Create("Public")))),
        ],
    };
}
