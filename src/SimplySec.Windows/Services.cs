using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml;
using System.Xml.Linq;
using Serilog;
using SimplySec.Core.Actions;
using SimplySec.Core.Compat;
using SimplySec.Core.Lan;
using SimplySec.Core.Model;
using SimplySec.Windows.Interop;

namespace SimplySec.Windows;

/// <summary>System settings through CIM methods (the providers behind the SMB, Defender and restore cmdlets).</summary>
public sealed class SystemSetters : ISystemAdapter
{
    private static void Check(System.Management.ManagementBaseObject? result, string what, params uint[] ok)
    {
        var rc = result?["ReturnValue"] is { } v ? Convert.ToUInt32(v, CultureInfo.InvariantCulture) : 0u;
        if (!(ok.Length == 0 ? rc == 0 : ok.Contains(rc)))
        {
            throw new CommandException($"{what} returned {rc}");
        }
    }

    public JsonObject SmbServerGet() =>
        new() { ["smb1"] = Wmi.Bool(NativeFacts.SmbServerConfiguration(), "EnableSMB1Protocol") };

    public void SmbServerSet(bool smb1) =>
        Check(Wmi.ClassMethod(Wmi.Smb, "MSFT_SmbServerConfiguration", "SetConfiguration", new Dictionary<string, object> { ["EnableSMB1Protocol"] = smb1 }),
            "Set-SmbServerConfiguration");

    public JsonObject DefenderGet()
    {
        var p = Wmi.First(Wmi.Defender, "SELECT EnableControlledFolderAccess FROM MSFT_MpPreference") ?? throw new CommandException("Get-MpPreference returned nothing");
        return new JsonObject { ["controlled_folder_access"] = (int)Wmi.Long(p, "EnableControlledFolderAccess") };
    }

    public void DefenderSetCfa(int mode) =>
        Check(Wmi.ClassMethod(Wmi.Defender, "MSFT_MpPreference", "Set", new Dictionary<string, object> { ["EnableControlledFolderAccess"] = (byte)mode }),
            "Set-MpPreference");

    public void UpdateSignatures() =>
        Check(Wmi.ClassMethod(Wmi.Defender, "MSFT_MpSignature", "Update", new Dictionary<string, object>()), "Update-MpSignature");

    private static System.Management.ManagementObject AdapterConfig(int configIndex) =>
        Wmi.Query(Wmi.Cimv2, $"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE Index = {configIndex.ToString(CultureInfo.InvariantCulture)}")
            .OfType<System.Management.ManagementObject>().FirstOrDefault()
        ?? throw new CommandException($"network adapter configuration {configIndex} not found");

    public int NetbiosGet(int configIndex) =>
        AdapterConfig(configIndex)["TcpipNetbiosOptions"] is { } v ? Convert.ToInt32(v, CultureInfo.InvariantCulture)
        : throw new CommandException($"network adapter configuration {configIndex} has no NetBIOS setting");

    /// <summary>
    /// 0 = default (DHCP decides), 1 = enabled, 2 = disabled. Windows refuses 0 on an adapter
    /// without DHCP (return value 100), so undoing "NetBIOS off" there failed in v2; the stored
    /// setting the method would have written (NetBT's NetbiosOptions) is set directly instead.
    /// </summary>
    public void NetbiosSet(int configIndex, int option)
    {
        var adapter = AdapterConfig(configIndex);
        var result = Wmi.InstanceMethod(adapter, "SetTcpipNetbios", new Dictionary<string, object> { ["TcpipNetbiosOptions"] = (uint)option });
        var rc = result?["ReturnValue"] is { } v ? Convert.ToUInt32(v, CultureInfo.InvariantCulture) : 0u;
        if (rc == 100 && option == 0 && adapter["SettingID"] is string guid)
        {
            using var key = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64)
                .OpenSubKey($@"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{guid}", writable: true)
                ?? throw new CommandException($"SetTcpipNetbios returned 100 and the NetBT settings of {guid} were not found");
            key.SetValue("NetbiosOptions", 0, Microsoft.Win32.RegistryValueKind.DWord);
            Log.Information("NetBIOS default restored in the registry for {Guid} (no DHCP on this adapter)", guid);
            return;
        }
        Check(result, "SetTcpipNetbios", 0, 1);
    }

    /// <summary>
    /// Checkpoint-Computer -RestorePointType MODIFY_SETTINGS (SystemRestore.CreateRestorePoint).
    /// Windows makes at most one restore point a day and skips later requests without an error.
    /// </summary>
    public void CreateRestorePoint(string description)
    {
        Check(Wmi.ClassMethod(@"root\default", "SystemRestore", "CreateRestorePoint", new Dictionary<string, object>
        {
            ["Description"] = description.Length > 60 ? description[..60] : description,
            ["RestorePointType"] = 12u, // MODIFY_SETTINGS
            ["EventType"] = 100u, // BEGIN_SYSTEM_CHANGE
        }), "Checkpoint-Computer");
        Log.Information("restore point requested: {Description}", description);
    }

    public static readonly IReadOnlyDictionary<string, string> SettingsUris = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["windows_security"] = "windowsdefender:",
        ["virus_protection"] = "windowsdefender://threat",
        ["ransomware"] = "windowsdefender://ransomwareprotection",
        ["windows_update"] = "ms-settings:windowsupdate",
        ["bitlocker"] = "ms-settings:deviceencryption",
        ["network"] = "ms-settings:network-status",
        ["remote_desktop"] = "ms-settings:remotedesktop",
        ["sharing"] = "ms-settings:network-advancedsettings",
    };

    public static void OpenSettings(string target)
    {
        if (!SettingsUris.TryGetValue(target, out var uri))
        {
            throw new ArgumentException($"unknown settings page {target}");
        }
        Process.Start(new ProcessStartInfo(uri) { UseShellExecute = true })?.Dispose();
    }
}

/// <summary>What is in use right now: evidence for "what would this fix affect?" (the usage fact).</summary>
public static partial class Usage
{
    public static JsonArray InboundConnections(List<Listener> listeners)
    {
        var listening = listeners.Where(x => x.Protocol == "tcp").Select(x => (x.Port, x.Pid)).ToHashSet();
        var names = new Dictionary<int, string>();
        foreach (var x in listeners)
        {
            names[x.Pid] = x.Process;
        }
        var output = new JsonArray();
        foreach (var c in Listeners.EstablishedTcp())
        {
            if (c.RemoteIp.Length == 0 || !listening.Contains((c.LocalPort, c.Pid)))
            {
                continue;
            }
            if (c.RemoteIp.StartsWith("127.", StringComparison.Ordinal) || c.RemoteIp.StartsWith("::1", StringComparison.Ordinal) || c.RemoteIp.StartsWith("::ffff:127.", StringComparison.Ordinal))
            {
                continue;
            }
            output.Add(new JsonObject
            {
                ["protocol"] = "tcp",
                ["local_port"] = c.LocalPort,
                ["local_ip"] = c.LocalIp,
                ["remote_ip"] = c.RemoteIp,
                ["pid"] = c.Pid,
                ["process"] = names.GetValueOrDefault(c.Pid, ""),
            });
        }
        return output;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WtsSessionInfo
    {
        public int SessionId;
        public IntPtr pWinStationName;
        public int State;
    }

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "WTSEnumerateSessionsW")]
    private static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr info, out int count);

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "WTSQuerySessionInformationW")]
    internal static extern bool WTSQuerySessionInformation(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);

    [DllImport("wtsapi32.dll")]
    internal static extern void WTSFreeMemory(IntPtr memory);

    private const int WtsClientProtocolType = 16;

    public static JsonArray RdpSessions()
    {
        var output = new JsonArray();
        if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var info, out var count))
        {
            return output;
        }
        try
        {
            var size = Marshal.SizeOf<WtsSessionInfo>();
            for (var i = 0; i < count; i++)
            {
                var s = Marshal.PtrToStructure<WtsSessionInfo>(info + i * size);
                if (!WTSQuerySessionInformation(IntPtr.Zero, s.SessionId, WtsClientProtocolType, out var buf, out _))
                {
                    continue;
                }
                var proto = Marshal.ReadInt16(buf);
                WTSFreeMemory(buf);
                if (proto == 2 && s.State == 0)
                {
                    output.Add(new JsonObject { ["session"] = s.SessionId, ["station"] = Marshal.PtrToStringUni(s.pWinStationName) ?? "" });
                }
            }
        }
        finally
        {
            WTSFreeMemory(info);
        }
        return output;
    }

    public static JsonObject Collect(List<Listener> listeners)
    {
        var value = new JsonObject();
        try
        {
            value["connections"] = InboundConnections(listeners);
        }
        catch (Exception exc)
        {
            Log.Warning("connections: {Error}", exc.Message);
            value["connections"] = new JsonArray();
        }
        value["remote_session"] = Native.GetSystemMetrics(0x1000) != 0;
        value["rdp_sessions"] = RdpSessions();
        value["msra_running"] = Listeners.ProcessSnapshot().Values.Any(p => PyStr.Lower(p.Name) == "msra.exe");
        value["hostname"] = Dns.GetHostName();
        foreach (var (k, v) in Extra())
        {
            value[k] = v?.DeepClone();
        }
        return new JsonObject { ["status"] = "ok", ["value"] = value };
    }

    // MSFT_SmbMapping.Status, written by name as [string]$_.Status did.
    private static readonly string[] MappingStatus = ["OK", "Paused", "Disconnected", "NetworkError", "Connecting", "Reconnecting", "Unavailable"];

    private static JsonArray Rows(Func<IEnumerable<JsonNode>> read, string what)
    {
        try
        {
            return new JsonArray([.. read()]);
        }
        catch (Exception exc)
        {
            Log.Information("usage {What}: {Error}", what, exc.Message);
            return [];
        }
    }

    /// <summary>Mapped drives, network printers, SMB sessions and last logons (v2's usage script, natively).</summary>
    public static JsonObject Extra()
    {
        var output = new JsonObject
        {
            ["mappings"] = Rows(() => Wmi.Query(Wmi.Smb, "SELECT LocalPath, RemotePath, Status FROM MSFT_SmbMapping").Select(m =>
            {
                var status = Wmi.Long(m, "Status");
                return (JsonNode)new JsonObject
                {
                    ["local"] = Wmi.Prop(m, "LocalPath"),
                    ["remote"] = Wmi.Prop(m, "RemotePath"),
                    ["status"] = status >= 0 && status < MappingStatus.Length ? MappingStatus[(int)status] : status.ToString(CultureInfo.InvariantCulture),
                };
            }), "mappings"),
            ["printers"] = Rows(() => Wmi.Query(Wmi.StandardCimv2, "SELECT Name, PortName, ComputerName, Type FROM MSFT_Printer")
                .Where(p =>
                {
                    var port = Wmi.Str(p, "PortName");
                    return Wmi.Long(p, "Type") == 1 || port.StartsWith(@"\\", StringComparison.OrdinalIgnoreCase)
                           || port.StartsWith("WSD", StringComparison.OrdinalIgnoreCase) || port.StartsWith("IP_", StringComparison.OrdinalIgnoreCase);
                })
                .Select(p => (JsonNode)new JsonObject { ["name"] = Wmi.Prop(p, "Name"), ["port"] = Wmi.Prop(p, "PortName"), ["computer"] = Wmi.Prop(p, "ComputerName") }), "printers"),
        };
        try
        {
            output["smb_sessions"] = new JsonArray([.. Wmi.Query(Wmi.Smb, "SELECT ClientComputerName, ClientUserName, Dialect FROM MSFT_SmbSession")
                .Select(s => (JsonNode)new JsonObject { ["client"] = Wmi.Prop(s, "ClientComputerName"), ["user"] = Wmi.Prop(s, "ClientUserName"), ["dialect"] = Wmi.Str(s, "Dialect") })]);
            output["smb_sessions_status"] = "ok";
        }
        catch (Exception)
        {
            output["smb_sessions"] = new JsonArray();
            output["smb_sessions_status"] = "needs_admin";
        }
        output["last_logons"] = Rows(() => LocalUsers.List().Select(u => (JsonNode)new JsonObject
        {
            ["sid"] = u.Sid,
            ["last"] = u.LastLogon is { } d ? d.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture) : null,
        }), "last logons");
        return output;
    }
}

/// <summary>Saved Wi-Fi profiles via netsh wlan export (no keys); P6 moves this to the WLAN API.</summary>
public sealed class Wifi : IWifiAdapter
{
    private const string Ns = "http://www.microsoft.com/networking/WLAN/profile/v1";
    private static readonly string Netsh = Path.Combine(Runner.System32, "netsh.exe");

    public sealed record Profile(string Name, string Ssid, string ConnectionMode, string Authentication, string Encryption)
    {
        public string? Weak
        {
            get
            {
                var auth = PyStr.Lower(Authentication);
                var enc = PyStr.Lower(Encryption);
                if (auth == "open" && enc is "none" or "")
                {
                    return "open (no password, no encryption)";
                }
                if (enc == "wep" || auth == "shared")
                {
                    return "WEP (broken encryption)";
                }
                if (enc == "tkip")
                {
                    return "TKIP (outdated encryption)";
                }
                if (auth is "wpapsk" or "wpa")
                {
                    return "WPA (outdated)";
                }
                return null;
            }
        }

        public JsonObject ToJson() => new()
        {
            ["name"] = Name,
            ["ssid"] = Ssid,
            ["connection_mode"] = ConnectionMode,
            ["authentication"] = Authentication,
            ["encryption"] = Encryption,
            ["weak"] = Weak,
        };
    }

    public static Profile? ParseProfile(string xml)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        using var reader = XmlReader.Create(new StringReader(xml), settings);
        var root = XElement.Load(reader);
        XNamespace ns = Ns;
        string Text(params string[] path)
        {
            XElement? el = root;
            foreach (var p in path)
            {
                el = el?.Element(ns + p);
            }
            return el is null ? "" : PyStr.Strip(Ssdp.Text(el) ?? "");
        }
        var name = Text("name");
        if (name.Length == 0)
        {
            return null;
        }
        var ssid = Text("SSIDConfig", "SSID", "name");
        var mode = Text("connectionMode");
        return new Profile(name, ssid.Length > 0 ? ssid : name, mode.Length > 0 ? mode : "auto",
            Text("MSM", "security", "authEncryption", "authentication"), Text("MSM", "security", "authEncryption", "encryption"));
    }

    private static List<Profile> Export(string? name = null)
    {
        var folder = Path.Combine(Path.GetTempPath(), "simplysec-wlan-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(folder);
        try
        {
            List<string> args = [Netsh, "wlan", "export", "profile", $"folder={folder}"];
            if (name is not null)
            {
                args.Insert(4, $"name={name}");
            }
            var res = Runner.Run(args, timeout: 30);
            var files = Directory.GetFiles(folder, "*.xml");
            if (!res.Ok && files.Length == 0)
            {
                return [];
            }
            var output = new List<Profile>();
            foreach (var f in files)
            {
                try
                {
                    var p = ParseProfile(File.ReadAllText(f, Encoding.UTF8));
                    if (p is not null)
                    {
                        output.Add(p);
                    }
                }
                catch (XmlException exc)
                {
                    Log.Warning("could not parse a Wi-Fi profile: {Error}", exc.Message);
                }
            }
            return output;
        }
        finally
        {
            try
            {
                Directory.Delete(folder, true);
            }
            catch (IOException)
            {
            }
        }
    }

    public static List<Profile> Profiles() => Export();

    public static JsonObject Fact()
    {
        try
        {
            return new JsonObject { ["status"] = "ok", ["value"] = new JsonArray(Profiles().Select(p => (JsonNode)p.ToJson()).ToArray()) };
        }
        catch (Exception exc)
        {
            return new JsonObject { ["status"] = "error", ["error"] = exc.Message };
        }
    }

    public string GetConnectionMode(string profileName)
    {
        var found = Export(profileName).Where(p => p.Name == profileName).ToList();
        if (found.Count == 0)
        {
            throw new CommandException($"Wi-Fi profile '{profileName}' not found");
        }
        return found[0].ConnectionMode;
    }

    public void SetConnectionMode(string profileName, string mode)
    {
        if (mode is not ("auto" or "manual"))
        {
            throw new ArgumentException("mode must be auto or manual");
        }
        Runner.Run([Netsh, "wlan", "set", "profileparameter", $"name={profileName}", $"connectionmode={mode}"], timeout: 30, check: true);
    }
}

/// <summary>The daily check as a Task Scheduler task, created from XML (locale-neutral).</summary>
public sealed partial class Scheduler : ISchedulerAdapter
{
    private static readonly string Schtasks = Path.Combine(Runner.System32, "schtasks.exe");

    /// <summary>The program and arguments the task runs (the windowed app, so no console flashes).</summary>
    public static Func<(string Exe, string Args)> Command { get; set; } = () => Elevation.CommandFor(["monitor", "--run"], gui: true);

    [System.Text.RegularExpressions.GeneratedRegex("^([01]\\d|2[0-3]):[0-5]\\d$")]
    private static partial System.Text.RegularExpressions.Regex TimeOfDay();

    private static string Esc(string s) => s.Replace("&", "&amp;", StringComparison.Ordinal).Replace(">", "&gt;", StringComparison.Ordinal).Replace("<", "&lt;", StringComparison.Ordinal);

    public static string BuildXml(string time, string command, string arguments, string userSid, DateOnly? today = null)
    {
        if (!TimeOfDay().IsMatch(time) || time.Contains('\n'))
        {
            throw new ArgumentException("time must be HH:MM");
        }
        var start = (today ?? DateOnly.FromDateTime(DateTime.Now)).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + $"T{time}:00";
        return $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo>
                <Author>SimplySec</Author>
                <Description>SimplySec daily read-only security check. It never changes settings. Remove it in SimplySec (Settings or Changes).</Description>
              </RegistrationInfo>
              <Triggers>
                <CalendarTrigger>
                  <StartBoundary>{start}</StartBoundary>
                  <Enabled>true</Enabled>
                  <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
                </CalendarTrigger>
              </Triggers>
              <Principals>
                <Principal id="Author">
                  <UserId>{Esc(userSid)}</UserId>
                  <LogonType>InteractiveToken</LogonType>
                  <RunLevel>HighestAvailable</RunLevel>
                </Principal>
              </Principals>
              <Settings>
                <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                <StartWhenAvailable>true</StartWhenAvailable>
                <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
                <ExecutionTimeLimit>PT30M</ExecutionTimeLimit>
                <Enabled>true</Enabled>
                <Hidden>false</Hidden>
              </Settings>
              <Actions Context="Author">
                <Exec>
                  <Command>{Esc(command)}</Command>
                  <Arguments>{Esc(arguments)}</Arguments>
                </Exec>
              </Actions>
            </Task>

            """;
    }

    /// <summary>
    /// The signed-in user of this session (not the elevated account, which can differ when
    /// someone elevates with another administrator's credentials).
    /// </summary>
    public static string SignedInUserSid()
    {
        const int wtsUserName = 5, wtsDomainName = 7;
        var session = System.Diagnostics.Process.GetCurrentProcess().SessionId;
        string? Query(int cls)
        {
            if (!Usage.WTSQuerySessionInformation(IntPtr.Zero, session, cls, out var buf, out _))
            {
                return null;
            }
            try
            {
                return Marshal.PtrToStringUni(buf);
            }
            finally
            {
                Usage.WTSFreeMemory(buf);
            }
        }
        var user = Query(wtsUserName);
        var domain = Query(wtsDomainName);
        if (!string.IsNullOrEmpty(user))
        {
            try
            {
                var account = new NTAccount(string.IsNullOrEmpty(domain) ? user : $"{domain}\\{user}");
                return ((SecurityIdentifier)account.Translate(typeof(SecurityIdentifier))).Value;
            }
            catch (IdentityNotMappedException)
            {
            }
        }
        return WindowsIdentity.GetCurrent().User!.Value;
    }

    public bool Exists(string name) => Runner.Run([Schtasks, "/Query", "/TN", name], timeout: 30).Ok;

    public string? ExportXml(string name)
    {
        var res = Runner.Run([Schtasks, "/Query", "/TN", name, "/XML"], timeout: 30);
        return res.Ok && res.Stdout.Contains("<Task", StringComparison.Ordinal) ? res.Stdout : null;
    }

    private static void CreateFromXml(string name, string xml)
    {
        var dir = Path.Combine(Path.GetTempPath(), "simplysec-task-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        try
        {
            var path = Path.Combine(dir, "task.xml");
            File.WriteAllText(path, xml, Encoding.Unicode);
            Runner.Run([Schtasks, "/Create", "/TN", name, "/XML", path, "/F"], timeout: 60, check: true);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    public void Create(string name, string time)
    {
        var (exe, args) = Command();
        CreateFromXml(name, BuildXml(time, exe, args, SignedInUserSid()));
        Log.Information("scheduled task created: {Name} at {Time}", name, time);
    }

    public void Delete(string name)
    {
        if (Exists(name))
        {
            Runner.Run([Schtasks, "/Delete", "/TN", name, "/F"], timeout: 30, check: true);
        }
    }

    public void Restore(string name, string? xml)
    {
        if (!string.IsNullOrEmpty(xml))
        {
            CreateFromXml(name, xml);
        }
        else
        {
            Delete(name);
        }
    }
}

/// <summary>
/// Windows toast notifications through WinRT, shown as "SimplySec": the app id is registered for
/// the current user (HKCU\Software\Classes\AppUserModelId, as unpackaged apps do). If Windows
/// won't show it under that id, v2's PowerShell app id is used instead (no PowerShell runs).
/// </summary>
public static class Toast
{
    public const string AppId = "SimplySec.DailyCheck";
    private const string PowerShellAppId = @"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe";

    /// <summary>Register (or refresh) the app id's display name and icon for this user.</summary>
    public static void Register()
    {
        using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey($@"Software\Classes\AppUserModelId\{AppId}");
        key.SetValue("DisplayName", "SimplySec");
        var exe = Elevation.CommandFor([], gui: true).Exe;
        if (File.Exists(exe))
        {
            key.SetValue("IconUri", exe);
        }
    }

    private static void ShowAs(string appId, string xml)
    {
        var doc = new global::Windows.Data.Xml.Dom.XmlDocument();
        doc.LoadXml(xml);
        var notifier = global::Windows.UI.Notifications.ToastNotificationManager.CreateToastNotifier(appId);
        notifier.Show(new global::Windows.UI.Notifications.ToastNotification(doc));
        // Turned off for this app in Settings: report it, so the caller can try the other id.
        if (notifier.Setting != global::Windows.UI.Notifications.NotificationSetting.Enabled)
        {
            throw new InvalidOperationException($"notifications for {appId}: {notifier.Setting}");
        }
    }

    private static string Esc(string s) => s.Replace("&", "&amp;", StringComparison.Ordinal).Replace(">", "&gt;", StringComparison.Ordinal).Replace("<", "&lt;", StringComparison.Ordinal);

    public static string ToastXml(string title, List<string> lines) =>
        "<toast><visual><binding template=\"ToastGeneric\">" +
        $"<text>{Esc(title.Length > 120 ? title[..120] : title)}</text>" +
        string.Concat(lines.Take(2).Select(l => $"<text>{Esc(l.Length > 200 ? l[..200] : l)}</text>")) +
        "</binding></visual></toast>";

    public static bool Show(string title, List<string> lines)
    {
        var xml = ToastXml(title, lines);
        try
        {
            Register();
            ShowAs(AppId, xml);
            return true;
        }
        catch (Exception exc)
        {
            Log.Information("toast as SimplySec failed ({Type} 0x{HResult:X8} {Error}); using the PowerShell app id", exc.GetType().Name, exc.HResult, exc.Message);
        }
        try
        {
            ShowAs(PowerShellAppId, xml);
            return true;
        }
        catch (Exception exc)
        {
            Log.Warning("toast failed: {Error}", exc.Message);
            return false;
        }
    }
}

/// <summary>Optional nmap deep scan of a confirmed home network (nmap is never bundled).</summary>
public static class Nmap
{
    public static string? Find()
    {
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var p = Path.Combine(dir.Trim(), "nmap.exe");
            if (File.Exists(p))
            {
                return p;
            }
        }
        foreach (var root in new[] { Environment.GetEnvironmentVariable("ProgramFiles(x86)") ?? @"C:\Program Files (x86)", Environment.GetEnvironmentVariable("ProgramFiles") ?? @"C:\Program Files" })
        {
            var p = Path.Combine(root, "Nmap", "nmap.exe");
            if (File.Exists(p))
            {
                return p;
            }
        }
        return null;
    }

    public static string? MacPrefixesFile()
    {
        var exe = Find();
        if (exe is null)
        {
            return null;
        }
        var f = Path.Combine(Path.GetDirectoryName(exe)!, "nmap-mac-prefixes");
        return File.Exists(f) ? f : null;
    }

    /// <summary>nmap's XML has a DOCTYPE but no entities: DTD ignored, no resolver.</summary>
    public static List<NmapHost> ParseXml(string xml)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null };
        using var reader = XmlReader.Create(new StringReader(xml), settings);
        var root = XElement.Load(reader);
        var hosts = new List<NmapHost>();
        foreach (var h in root.DescendantsAndSelf("host"))
        {
            var status = h.Element("status");
            if (status is not null && (string?)status.Attribute("state") != "up")
            {
                continue;
            }
            string ip = "", mac = "", vendor = "", hostname = "";
            foreach (var addr in h.Elements("address"))
            {
                var type = (string?)addr.Attribute("addrtype");
                if (type == "ipv4")
                {
                    ip = (string?)addr.Attribute("addr") ?? "";
                }
                else if (type == "mac")
                {
                    mac = (string?)addr.Attribute("addr") ?? "";
                    vendor = (string?)addr.Attribute("vendor") ?? "";
                }
            }
            var hn = h.Element("hostnames")?.Element("hostname");
            if (hn is not null)
            {
                hostname = (string?)hn.Attribute("name") ?? "";
            }
            var services = new List<NmapService>();
            foreach (var p in h.Descendants("port"))
            {
                var st = p.Element("state");
                var svc = p.Element("service");
                services.Add(new NmapService(
                    int.Parse((string?)p.Attribute("portid") ?? "0", CultureInfo.InvariantCulture),
                    (string?)p.Attribute("protocol") ?? "tcp",
                    (string?)st?.Attribute("state") ?? "",
                    (string?)svc?.Attribute("name") ?? "",
                    (string?)svc?.Attribute("product") ?? "",
                    (string?)svc?.Attribute("version") ?? ""));
            }
            if (ip.Length > 0)
            {
                hosts.Add(new NmapHost(ip, mac, vendor, hostname, services));
            }
        }
        return hosts;
    }

    public static List<NmapHost> ServiceScan(List<string> targets, List<int> ports, double timeout = 600)
    {
        var exe = Find() ?? throw new FileNotFoundException("nmap is not installed");
        List<string> args = [exe, "-sV", "-Pn", "--open", "-T4", "-p", string.Join(',', ports), "-oX", "-", .. targets];
        return ParseXml(Runner.Run(args, timeout, check: true).Stdout);
    }
}

/// <summary>The OS parts of a home-network scan.</summary>
public sealed class WindowsLanHost : ILanHost
{
    private static readonly Lazy<OuiDatabase> Db = new(() =>
    {
        var bundled = OuiDatabase.Default;
        if (bundled.Entries.Count > 0)
        {
            return bundled;
        }
        var prefixes = Nmap.MacPrefixesFile();
        return prefixes is null ? bundled : OuiDatabase.FromNmap(File.ReadAllText(prefixes));
    });

    public Dictionary<string, string> Neighbors(int interfaceIndex) => Network.Neighbors(interfaceIndex);
    public List<NmapHost> NmapScan(List<string> ips, List<int> ports) => Nmap.ServiceScan(ips, ports);
    public OuiDatabase Oui => Db.Value;
    public ISsdp Ssdp => Core.Lan.Ssdp.Instance;
}
