using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Serilog;

namespace SimplySec.Windows;

/// <summary>
/// The facts that facts.ps1 collected, read natively (WMI/CIM, registry, netapi32, COM) with the
/// identical JSON: same keys and order, every item <c>{status, value | error}</c>, and PowerShell's
/// own quirks kept where the checks see them (DWORDs as signed ints; a list fact with one entry
/// is that entry, with none it is <c>{}</c>). Only error texts differ.
/// </summary>
public static partial class NativeFacts
{
    private const string HklmTs = @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server";
    private const string HklmRdp = @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
    private const string PolTs = @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
    private const string HklmRa = @"HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance";
    private const string PolSys = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    private const string Lsa = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";
    private const string PolDns = @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
    private const string ExplHklm = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    private const string ExplHkcu = @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    private const string WuUx = @"HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings";
    private const string NetBt = @"HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces";

    private static readonly (string Name, Func<JsonNode?> Read)[] Items =
    [
        ("system", SystemInfo),
        ("network", NetworkInfo),
        ("defender", DefenderStatus),
        ("defender_prefs", DefenderPrefs),
        ("antivirus", Antivirus),
        ("smb", SmbConfig),
        ("shares", Shares),
        ("updates", Updates),
        ("uac", Uac),
        ("accounts", Accounts),
        ("rdp", Rdp),
        ("llmnr", () => new JsonObject { ["enable_multicast_policy"] = PsRegistry.Value(PolDns, "EnableMulticast") }),
        ("autorun", Autorun),
        ("bitlocker", BitLocker),
        ("firewall_policy", FirewallPolicy),
    ];

    /// <summary>All facts, read in parallel; the same shape as facts.ps1's output.</summary>
    public static JsonObject Collect()
    {
        var output = new JsonObject { ["collected"] = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture) };
        var tasks = Items.Select(i => Task.Run(() => Fact(i.Name, i.Read))).ToArray();
        Task.WaitAll(tasks);
        for (var i = 0; i < Items.Length; i++)
        {
            output[Items[i].Name] = tasks[i].Result;
        }
        return output;
    }

    /// <summary>facts.ps1's Fact: ok with the value, needs_admin for access denied, else error.</summary>
    public static JsonObject Fact(string name, Func<JsonNode?> read)
    {
        try
        {
            return new JsonObject { ["status"] = "ok", ["value"] = read() };
        }
        catch (Exception e)
        {
            var inner = e is AggregateException { InnerException: { } x } ? x : e;
            Log.Information("fact {Name}: {Error}", name, inner.Message);
            return new JsonObject { ["status"] = Wmi.IsAccessDenied(inner) ? "needs_admin" : "error", ["error"] = inner.Message };
        }
    }

    /// <summary>
    /// A list returned from a PowerShell script block: none is AutomationNull (written as {}),
    /// one is the item itself, more stay a list.
    /// </summary>
    public static JsonNode PsUnwrap(List<JsonNode> items) => items.Count switch
    {
        0 => new JsonObject(),
        1 => items[0],
        _ => new JsonArray([.. items]),
    };

    /// <summary>IsoDate: ([datetime]$d).ToUniversalTime().ToString('o').</summary>
    private static JsonNode? IsoDate(DateTime? d) => d is { } v ? JsonValue.Create(v.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture)) : null;

    // ------------------------------------------------------------------ items

    private static JsonNode SystemInfo()
    {
        var os = Wmi.First(Wmi.Cimv2, "SELECT Caption, Version, BuildNumber FROM Win32_OperatingSystem") ?? throw new InvalidOperationException("Win32_OperatingSystem returned nothing");
        var cs = Wmi.First(Wmi.Cimv2, "SELECT PartOfDomain, Domain FROM Win32_ComputerSystem") ?? throw new InvalidOperationException("Win32_ComputerSystem returned nothing");
        var chassis = new JsonArray();
        foreach (var e in Wmi.Query(Wmi.Cimv2, "SELECT ChassisTypes FROM Win32_SystemEnclosure"))
        {
            if (Wmi.Get(e, "ChassisTypes") is ushort[] types)
            {
                foreach (var t in types.Where(t => t != 0))
                {
                    chassis.Add(JsonValue.Create((int)t));
                }
            }
        }
        bool battery;
        try
        {
            battery = Wmi.Query(Wmi.Cimv2, "SELECT DeviceID FROM Win32_Battery").Count > 0;
        }
        catch (Exception)
        {
            battery = false; // -ErrorAction SilentlyContinue
        }
        return new JsonObject
        {
            ["computer"] = Environment.GetEnvironmentVariable("COMPUTERNAME"),
            ["os_caption"] = Wmi.Prop(os, "Caption"),
            ["os_version"] = Wmi.Prop(os, "Version"),
            ["os_build"] = Wmi.Prop(os, "BuildNumber"),
            ["part_of_domain"] = Wmi.Bool(cs, "PartOfDomain"),
            ["domain"] = Wmi.Prop(cs, "Domain"),
            ["chassis"] = chassis,
            ["has_battery"] = battery,
            ["system_drive"] = Environment.GetEnvironmentVariable("SystemDrive"),
        };
    }

    private static string MacText(string permanent) =>
        string.Join('-', Enumerable.Range(0, permanent.Length / 2).Select(i => permanent.Substring(i * 2, 2)));

    private static JsonNode NetworkInfo()
    {
        var profiles = new JsonArray();
        foreach (var p in Wmi.Query(Wmi.StandardCimv2, "SELECT InterfaceIndex, InterfaceAlias, Name, NetworkCategory FROM MSFT_NetConnectionProfile"))
        {
            profiles.Add(new JsonObject
            {
                ["index"] = (int)Wmi.Long(p, "InterfaceIndex"),
                ["alias"] = Wmi.Prop(p, "InterfaceAlias"),
                ["name"] = Wmi.Prop(p, "Name"),
                ["category"] = (int)Wmi.Long(p, "NetworkCategory"),
            });
        }

        // Get-NetAdapter: the adapters that aren't hidden.
        var adapters = new JsonArray();
        var adapterIndexes = new HashSet<long>();
        foreach (var a in Wmi.Query(Wmi.StandardCimv2, "SELECT * FROM MSFT_NetAdapter"))
        {
            if (Wmi.Bool(a, "Hidden"))
            {
                continue;
            }
            var index = Wmi.Long(a, "InterfaceIndex");
            adapterIndexes.Add(index);
            adapters.Add(new JsonObject
            {
                ["index"] = (int)index,
                ["name"] = Wmi.Prop(a, "Name"),
                ["description"] = Wmi.Prop(a, "InterfaceDescription"),
                ["mac"] = MacText(Wmi.Str(a, "PermanentAddress")),
                ["up"] = Wmi.Long(a, "InterfaceOperationalStatus") == 1,
                ["if_type"] = (int)Wmi.Long(a, "InterfaceType"),
                ["medium"] = (int)Wmi.Long(a, "NdisPhysicalMedium"),
                ["virtual"] = Wmi.Bool(a, "Virtual"),
                ["hardware"] = Wmi.Bool(a, "HardwareInterface"),
            });
        }

        // Get-NetIPConfiguration: those adapters' IP interfaces, in IP-interface order, with the
        // default routes' next hops (IPv4 first) and DNS servers (IPv6 entries first).
        var order = new List<long>();
        foreach (var i in Wmi.Query(Wmi.StandardCimv2, "SELECT InterfaceIndex FROM MSFT_NetIPInterface"))
        {
            var idx = Wmi.Long(i, "InterfaceIndex");
            if (adapterIndexes.Contains(idx) && !order.Contains(idx))
            {
                order.Add(idx);
            }
        }
        var routes = Wmi.Query(Wmi.StandardCimv2, "SELECT InterfaceIndex, DestinationPrefix, NextHop, Store FROM MSFT_NetRoute WHERE DestinationPrefix = '0.0.0.0/0' OR DestinationPrefix = '::/0'")
            .Where(r => Wmi.Long(r, "Store") == 1)
            .ToList();
        var dnsRows = Wmi.Query(Wmi.StandardCimv2, "SELECT InterfaceIndex, AddressFamily, ServerAddresses FROM MSFT_DNSClientServerAddress");
        var ip = new JsonArray();
        foreach (var idx in order)
        {
            var gw = new JsonArray();
            foreach (var prefix in new[] { "0.0.0.0/0", "::/0" })
            {
                foreach (var r in routes.Where(r => Wmi.Long(r, "InterfaceIndex") == idx && Wmi.Str(r, "DestinationPrefix") == prefix))
                {
                    gw.Add(Wmi.Prop(r, "NextHop"));
                }
            }
            var dns = new JsonArray();
            foreach (var family in new[] { 23L, 2L })
            {
                foreach (var d in dnsRows.Where(d => Wmi.Long(d, "InterfaceIndex") == idx && Wmi.Long(d, "AddressFamily") == family))
                {
                    if (Wmi.Get(d, "ServerAddresses") is string[] servers)
                    {
                        foreach (var s in servers)
                        {
                            dns.Add(JsonValue.Create(s));
                        }
                    }
                }
            }
            ip.Add(new JsonObject { ["index"] = (int)idx, ["gateways"] = gw, ["dns"] = dns });
        }

        var cfg = new JsonArray();
        foreach (var c in Wmi.Query(Wmi.Cimv2, "SELECT InterfaceIndex, Index, Description, DHCPServer, TcpipNetbiosOptions, SettingID FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True"))
        {
            var guid = Wmi.Str(c, "SettingID");
            cfg.Add(new JsonObject
            {
                ["index"] = (int)Wmi.Long(c, "InterfaceIndex"),
                ["config_index"] = (int)Wmi.Long(c, "Index"),
                ["description"] = Wmi.Prop(c, "Description"),
                ["dhcp_server"] = Wmi.Prop(c, "DHCPServer"),
                ["netbios"] = Wmi.Prop(c, "TcpipNetbiosOptions"),
                ["netbios_stored"] = PsRegistry.Value($@"{NetBt}\Tcpip_{guid}", "NetbiosOptions"),
                ["guid"] = guid,
            });
        }
        return new JsonObject { ["profiles"] = profiles, ["adapters"] = adapters, ["ip"] = ip, ["config"] = cfg };
    }

    private static JsonNode DefenderStatus()
    {
        var m = Wmi.First(Wmi.Defender, "SELECT * FROM MSFT_MpComputerStatus") ?? throw new InvalidOperationException("Get-MpComputerStatus returned nothing");
        DateTime? updated = Wmi.Get(m, "AntivirusSignatureLastUpdated") is string s && s.Length > 0 ? ManagementDateTimeConverter.ToDateTime(s) : null;
        return new JsonObject
        {
            ["am_service"] = Wmi.Bool(m, "AMServiceEnabled"),
            ["antivirus"] = Wmi.Bool(m, "AntivirusEnabled"),
            ["realtime"] = Wmi.Bool(m, "RealTimeProtectionEnabled"),
            ["tamper"] = Wmi.Bool(m, "IsTamperProtected"),
            ["signature_age_days"] = (int)Wmi.Long(m, "AntivirusSignatureAge"),
            ["signature_updated"] = IsoDate(updated),
            ["running_mode"] = Wmi.Str(m, "AMRunningMode"),
        };
    }

    private static JsonNode DefenderPrefs()
    {
        var p = Wmi.First(Wmi.Defender, "SELECT EnableControlledFolderAccess FROM MSFT_MpPreference") ?? throw new InvalidOperationException("Get-MpPreference returned nothing");
        return new JsonObject { ["controlled_folder_access"] = (int)Wmi.Long(p, "EnableControlledFolderAccess") };
    }

    private static JsonNode Antivirus() => PsUnwrap(
        Wmi.Query(Wmi.SecurityCenter, "SELECT displayName, productState, pathToSignedProductExe FROM AntiVirusProduct")
            .Select(a => (JsonNode)new JsonObject
            {
                ["name"] = Wmi.Prop(a, "displayName"),
                ["state"] = (int)Wmi.Long(a, "productState"),
                ["exe"] = Wmi.Prop(a, "pathToSignedProductExe"),
            }).ToList());

    private static JsonNode SmbConfig()
    {
        var c = SmbServerConfiguration();
        return new JsonObject
        {
            ["smb1"] = Wmi.Bool(c, "EnableSMB1Protocol"),
            ["smb2"] = Wmi.Bool(c, "EnableSMB2Protocol"),
            ["signing_required"] = Wmi.Bool(c, "RequireSecuritySignature"),
        };
    }

    /// <summary>Get-SmbServerConfiguration: the class has no instances; GetConfiguration() returns it.</summary>
    public static ManagementBaseObject SmbServerConfiguration() =>
        Wmi.ClassMethod(Wmi.Smb, "MSFT_SmbServerConfiguration", "GetConfiguration", new Dictionary<string, object>())?["Output"] as ManagementBaseObject
        ?? throw new InvalidOperationException("Get-SmbServerConfiguration returned nothing");

    private static JsonNode Shares()
    {
        var items = new List<JsonNode>();
        foreach (var share in Wmi.Query(Wmi.Smb, "SELECT * FROM MSFT_SmbShare"))
        {
            if (Wmi.Bool(share, "Special"))
            {
                continue;
            }
            var access = new JsonArray();
            var result = Wmi.InstanceMethod((ManagementObject)share, "GetAccessControlEntry");
            if (result?["ACL"] is ManagementBaseObject[] acl)
            {
                foreach (var ace in acl)
                {
                    var account = Wmi.Str(ace, "AccountName");
                    string? sid = null;
                    try
                    {
                        sid = new NTAccount(account).Translate(typeof(SecurityIdentifier)).Value;
                    }
                    catch (Exception)
                    {
                    }
                    access.Add(new JsonObject
                    {
                        ["account"] = account,
                        ["sid"] = sid,
                        ["right"] = (int)Wmi.Long(ace, "AccessRight"),
                        ["allow"] = Wmi.Long(ace, "AccessControlType") == 0,
                    });
                }
            }
            items.Add(new JsonObject { ["name"] = Wmi.Prop(share, "Name"), ["path"] = Wmi.Prop(share, "Path"), ["access"] = access });
        }
        return PsUnwrap(items);
    }

    private static readonly string[] DefenderKbs = ["KB2267602", "KB4052623", "KB5007651", "KB915597"];

    [GeneratedRegex(@"KB\d{6,7}", RegexOptions.CultureInvariant)]
    private static partial Regex KbPattern();

    /// <summary>Newest real update install (not Defender definitions) from the Windows Update history.</summary>
    private static DateTime? LastHistoryInstall()
    {
        try
        {
            var type = Type.GetTypeFromProgID("Microsoft.Update.Session") ?? throw new InvalidOperationException("no WUA");
            dynamic session = Activator.CreateInstance(type)!;
            dynamic searcher = session.CreateUpdateSearcher();
            int count = searcher.GetTotalHistoryCount();
            DateTime? last = null;
            if (count > 0)
            {
                dynamic history = searcher.QueryHistory(0, Math.Min(count, 300));
                int n = history.Count;
                for (var i = 0; i < n; i++)
                {
                    dynamic h = history.Item(i);
                    int op = h.Operation;
                    int rc = h.ResultCode;
                    if (op != 1 || (rc != 2 && rc != 3))
                    {
                        continue;
                    }
                    var m = KbPattern().Match((string)(h.Title ?? ""));
                    if (!m.Success || DefenderKbs.Contains(m.Value))
                    {
                        continue;
                    }
                    DateTime date = h.Date;
                    if (last is null || date > last)
                    {
                        last = date;
                    }
                }
            }
            return last;
        }
        catch (Exception exc)
        {
            Log.Information("update history unavailable: {Error}", exc.Message);
            return null; // facts.ps1: try { ... } catch {}
        }
    }

    private static JsonNode Updates()
    {
        var lastHistory = LastHistoryInstall();
        // Win32_QuickFixEngineering.InstalledOn is "M/d/yyyy". facts.ps1 sorted by that date with
        // Sort-Object -Descending: .NET's unstable sort, so the same sort on the same order picks
        // the same hotfix among several installed the same day.
        var hotfixes = new List<(DateTime On, string Id)>();
        foreach (var q in Wmi.Query(Wmi.Cimv2, "SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering"))
        {
            var text = Wmi.Str(q, "InstalledOn");
            if (text.Length > 0 && DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var on))
            {
                hotfixes.Add((DateTime.SpecifyKind(on, DateTimeKind.Local), Wmi.Str(q, "HotFixID")));
            }
        }
        var sorted = hotfixes.ToArray();
        LegacyQuickSort(sorted, (a, b) => -a.On.CompareTo(b.On));
        (DateTime On, string Id)? qfe = sorted.Length > 0 ? sorted[0] : null;
        var reboot = PsRegistry.KeyExists(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")
                     || PsRegistry.KeyExists(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending");
        return new JsonObject
        {
            ["last_history_install"] = IsoDate(lastHistory),
            ["last_hotfix"] = qfe is { } a ? IsoDate(a.On) : null,
            ["last_hotfix_id"] = qfe is { } b ? b.Id : null,
            ["pause"] = new JsonObject
            {
                ["updates"] = PsRegistry.Value(WuUx, "PauseUpdatesExpiryTime"),
                ["quality"] = PsRegistry.Value(WuUx, "PauseQualityUpdatesEndTime"),
                ["feature"] = PsRegistry.Value(WuUx, "PauseFeatureUpdatesEndTime"),
            },
            ["reboot_pending"] = reboot,
        };
    }

    /// <summary>
    /// .NET Framework 4.0's Array.Sort (ArraySortHelper.QuickSort), which Windows PowerShell 5.1's
    /// Sort-Object ends up using. Unstable: equal items come out in this exact order.
    /// </summary>
    public static void LegacyQuickSort<T>(T[] keys, Comparison<T> compare)
    {
        if (keys.Length > 1)
        {
            QuickSort(keys, 0, keys.Length - 1, compare);
        }
    }

    private static void SwapIfGreater<T>(T[] keys, Comparison<T> compare, int a, int b)
    {
        if (a != b && compare(keys[a], keys[b]) > 0)
        {
            (keys[a], keys[b]) = (keys[b], keys[a]);
        }
    }

    private static void QuickSort<T>(T[] keys, int left, int right, Comparison<T> compare)
    {
        do
        {
            var i = left;
            var j = right;
            var middle = i + ((j - i) >> 1);
            SwapIfGreater(keys, compare, i, middle);
            SwapIfGreater(keys, compare, i, j);
            SwapIfGreater(keys, compare, middle, j);
            var x = keys[middle];
            do
            {
                while (compare(keys[i], x) < 0)
                {
                    i++;
                }
                while (compare(x, keys[j]) < 0)
                {
                    j--;
                }
                if (i > j)
                {
                    break;
                }
                if (i < j)
                {
                    (keys[i], keys[j]) = (keys[j], keys[i]);
                }
                i++;
                j--;
            }
            while (i <= j);
            if (j - left <= right - i)
            {
                if (left < j)
                {
                    QuickSort(keys, left, j, compare);
                }
                left = i;
            }
            else
            {
                if (i < right)
                {
                    QuickSort(keys, i, right, compare);
                }
                right = j;
            }
        }
        while (left < right);
    }

    private static JsonNode Uac() => new JsonObject
    {
        ["enable_lua"] = PsRegistry.Value(PolSys, "EnableLUA"),
        ["consent_admin"] = PsRegistry.Value(PolSys, "ConsentPromptBehaviorAdmin"),
        ["secure_desktop"] = PsRegistry.Value(PolSys, "PromptOnSecureDesktop"),
    };

    private static JsonNode Accounts() => new JsonObject
    {
        ["users"] = new JsonArray(LocalUsers.List().Select(u => (JsonNode)new JsonObject
        {
            ["name"] = u.Name,
            ["sid"] = u.Sid,
            ["enabled"] = u.Enabled,
            ["password_required"] = u.PasswordRequired,
        }).ToArray()),
        ["limit_blank_password_use"] = PsRegistry.Value(Lsa, "LimitBlankPasswordUse"),
    };

    private static JsonNode Rdp() => new JsonObject
    {
        ["deny"] = PsRegistry.Value(HklmTs, "fDenyTSConnections"),
        ["deny_policy"] = PsRegistry.Value(PolTs, "fDenyTSConnections"),
        ["nla"] = PsRegistry.Value(HklmRdp, "UserAuthentication"),
        ["nla_policy"] = PsRegistry.Value(PolTs, "UserAuthentication"),
        ["port"] = PsRegistry.Value(HklmRdp, "PortNumber"),
        ["remote_assistance"] = PsRegistry.Value(HklmRa, "fAllowToGetHelp"),
        ["remote_assistance_policy"] = PsRegistry.Value(PolTs, "fAllowToGetHelp"),
    };

    private static JsonNode Autorun() => new JsonObject
    {
        ["hklm"] = PsRegistry.Value(ExplHklm, "NoDriveTypeAutoRun"),
        ["hkcu"] = PsRegistry.Value(ExplHkcu, "NoDriveTypeAutoRun"),
        ["no_autorun_hklm"] = PsRegistry.Value(ExplHklm, "NoAutorun"),
    };

    /// <summary>The Explorer property System.Volume.BitLockerProtection of the system drive (STA COM).</summary>
    private static JsonNode BitLocker()
    {
        var drive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
        object? value = null;
        Exception? error = null;
        var thread = new Thread(() =>
        {
            try
            {
                var type = Type.GetTypeFromProgID("Shell.Application") ?? throw new InvalidOperationException("no Shell.Application");
                dynamic shell = Activator.CreateInstance(type)!;
                dynamic item = shell.NameSpace(17).ParseName(drive);
                value = item.ExtendedProperty("System.Volume.BitLockerProtection");
            }
            catch (Exception e)
            {
                error = e;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (error is not null)
        {
            throw error;
        }
        return new JsonObject { ["drive"] = drive, ["protection"] = Wmi.Json(value) };
    }

    private static JsonNode FirewallPolicy()
    {
        const string root = @"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall";
        var output = new JsonObject();
        foreach (var p in new[] { "DomainProfile", "PrivateProfile", "PublicProfile", "StandardProfile" })
        {
            output[p] = new JsonObject
            {
                ["enable"] = PsRegistry.Value($@"{root}\{p}", "EnableFirewall"),
                ["inbound"] = PsRegistry.Value($@"{root}\{p}", "DefaultInboundAction"),
            };
        }
        return output;
    }
}

/// <summary>Local user accounts through netapi32 (what Get-LocalUser returned), sorted by name like it.</summary>
public static class LocalUsers
{
    public sealed record User(string Name, string? Sid, bool Enabled, bool PasswordRequired, DateTime? LastLogon);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct UserInfo2
    {
        public IntPtr Name;
        public IntPtr Password;
        public uint PasswordAge;
        public uint Priv;
        public IntPtr HomeDir;
        public IntPtr Comment;
        public uint Flags;
        public IntPtr ScriptPath;
        public uint AuthFlags;
        public IntPtr FullName;
        public IntPtr UsrComment;
        public IntPtr Parms;
        public IntPtr Workstations;
        public uint LastLogon;
        public uint LastLogoff;
        public uint AcctExpires;
        public uint MaxStorage;
        public uint UnitsPerWeek;
        public IntPtr LogonHours;
        public uint BadPwCount;
        public uint NumLogons;
        public IntPtr LogonServer;
        public uint CountryCode;
        public uint CodePage;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UserInfo23
    {
        public IntPtr Name;
        public IntPtr FullName;
        public IntPtr Comment;
        public uint Flags;
        public IntPtr UserSid;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserEnum(string? server, int level, int filter, out IntPtr buf, int prefMax, out int read, out int total, ref int resume);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserGetInfo(string? server, string user, int level, out IntPtr buf);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buf);

    private const int FilterNormalAccount = 0x2;
    private const uint UfAccountDisable = 0x2;
    private const uint UfPasswdNotReqd = 0x20;

    public static List<User> List()
    {
        var resume = 0;
        var rc = NetUserEnum(null, 2, FilterNormalAccount, out var buf, -1, out var read, out _, ref resume);
        if (rc != 0)
        {
            throw new System.ComponentModel.Win32Exception(rc);
        }
        var users = new List<User>();
        try
        {
            var size = Marshal.SizeOf<UserInfo2>();
            for (var i = 0; i < read; i++)
            {
                var u = Marshal.PtrToStructure<UserInfo2>(buf + i * size);
                var name = Marshal.PtrToStringUni(u.Name) ?? "";
                DateTime? last = u.LastLogon == 0 ? null : DateTime.UnixEpoch.AddSeconds(u.LastLogon).ToLocalTime();
                users.Add(new User(name, Sid(name), (u.Flags & UfAccountDisable) == 0, (u.Flags & UfPasswdNotReqd) == 0, last));
            }
        }
        finally
        {
            NetApiBufferFree(buf);
        }
        return users.OrderBy(u => u.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static string? Sid(string name)
    {
        if (NetUserGetInfo(null, name, 23, out var buf) != 0)
        {
            return null;
        }
        try
        {
            var info = Marshal.PtrToStructure<UserInfo23>(buf);
            return info.UserSid == IntPtr.Zero ? null : new SecurityIdentifier(info.UserSid).Value;
        }
        finally
        {
            NetApiBufferFree(buf);
        }
    }
}
