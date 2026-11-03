using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using SimplySec.Core.Compat;
using SimplySec.Core.Model;
using SimplySec.Windows.Interop;

namespace SimplySec.Windows;

/// <summary>
/// Listening sockets with their exact program, services, user and AppContainer,
/// read directly with GetExtendedTcpTable/UdpTable (the same results psutil gave v2).
/// </summary>
public static class Listeners
{
    public const string SystemSid = "S-1-5-18";

    private static readonly Dictionary<string, string> AccountSids = new(StringComparer.Ordinal)
    {
        ["localsystem"] = SystemSid,
        ["nt authority\\system"] = SystemSid,
        ["nt authority\\localservice"] = "S-1-5-19",
        ["nt authority\\local service"] = "S-1-5-19",
        ["nt authority\\networkservice"] = "S-1-5-20",
        ["nt authority\\network service"] = "S-1-5-20",
    };

    private static readonly HashSet<string> AlwaysSystem = new(StringComparer.Ordinal)
    {
        "wininit.exe", "services.exe", "lsass.exe", "csrss.exe", "smss.exe", "winlogon.exe",
    };

    private sealed record Identity(string Name, string Exe, string? UserSid, string? PackageSid);

    internal sealed record ProcInfo(string Name, int ParentPid);

    // ------------------------------------------------------------------ processes

    internal static Dictionary<int, ProcInfo> ProcessSnapshot()
    {
        var output = new Dictionary<int, ProcInfo>();
        var snap = Native.CreateToolhelp32Snapshot(Native.Th32csSnapProcess, 0);
        if (snap == IntPtr.Zero || snap == new IntPtr(-1))
        {
            return output;
        }
        try
        {
            var entry = new Native.ProcessEntry32 { dwSize = (uint)Marshal.SizeOf<Native.ProcessEntry32>() };
            if (Native.Process32First(snap, ref entry))
            {
                do
                {
                    output[(int)entry.th32ProcessID] = new ProcInfo(entry.szExeFile, (int)entry.th32ParentProcessID);
                }
                while (Native.Process32Next(snap, ref entry));
            }
        }
        finally
        {
            Native.CloseHandle(snap);
        }
        return output;
    }

    /// <summary>
    /// Program path of a process, like psutil's Process.exe(): it works for every PID (including
    /// SYSTEM services when not elevated) because the kernel's image name is asked for by PID.
    /// </summary>
    internal static string ProcessExe(int pid)
    {
        if (pid == 0)
        {
            return "";
        }
        var h = Native.OpenProcess(Native.ProcessQueryLimitedInformation, false, pid);
        if (h != IntPtr.Zero)
        {
            try
            {
                var size = 32768;
                var sb = new StringBuilder(size);
                if (Native.QueryFullProcessImageName(h, 0, sb, ref size))
                {
                    return sb.ToString();
                }
            }
            finally
            {
                Native.CloseHandle(h);
            }
        }
        var nt = NtImageName(pid);
        return nt.Length > 0 ? ConvertDosPath(nt) : "";
    }

    /// <summary>NT image name ("\Device\HarddiskVolume3\...") of a PID; "" when unknown.</summary>
    internal static string NtImageName(int pid)
    {
        const int bytes = 65534; // UNICODE_STRING.MaximumLength is a USHORT
        var buf = Marshal.AllocHGlobal(bytes);
        try
        {
            var info = new Native.SystemProcessIdInformation
            {
                ProcessId = pid,
                Length = 0,
                MaximumLength = bytes,
                Buffer = buf,
            };
            var status = Native.NtQuerySystemInformation(Native.SystemProcessIdInformationClass, ref info,
                Marshal.SizeOf<Native.SystemProcessIdInformation>(), IntPtr.Zero);
            return status == 0 && info.Length > 0 ? Marshal.PtrToStringUni(buf, info.Length / 2) : "";
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    /// <summary>psutil's convert_dos_path: "\Device\HarddiskVolume1\x" → "C:\x".</summary>
    internal static string ConvertDosPath(string s)
    {
        if (s.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return s;
        }
        var parts = s.Split('\\');
        var rawdrive = string.Join('\\', parts.Take(3));
        string driveletter;
        if (rawdrive is @"\??\UNC" or @"\Device\Mup")
        {
            rawdrive = string.Join('\\', parts.Take(5));
            driveletter = @"\\" + string.Join('\\', parts.Skip(3).Take(2));
        }
        else if (rawdrive.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            driveletter = parts[2];
        }
        else
        {
            driveletter = DriveForDevice(rawdrive);
        }
        // ntpath.join(drive, remainder): the remainder is "" or starts with a backslash.
        return driveletter + s[rawdrive.Length..];
    }

    /// <summary>The "X:" whose DOS device target equals <paramref name="device"/> (case-sensitive), or "".</summary>
    private static string DriveForDevice(string device)
    {
        var target = new char[512];
        for (var c = 'A'; c <= 'Z'; c++)
        {
            var drive = string.Create(CultureInfo.InvariantCulture, $"{c}:");
            var n = Native.QueryDosDevice(drive, target, target.Length - 1);
            if (n == 0)
            {
                continue;
            }
            var first = new string(target, 0, Array.IndexOf(target, '\0') is var z and >= 0 ? z : n);
            if (first == device)
            {
                return drive;
            }
        }
        return "";
    }

    private static byte[]? TokenInfo(IntPtr token, int cls)
    {
        Native.GetTokenInformation(token, cls, IntPtr.Zero, 0, out var size);
        if (size == 0)
        {
            return null;
        }
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (!Native.GetTokenInformation(token, cls, buf, size, out size))
            {
                return null;
            }
            var bytes = new byte[size];
            Marshal.Copy(buf, bytes, 0, size);
            return bytes;
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    private static string? SidFromInfo(IntPtr token, int cls)
    {
        Native.GetTokenInformation(token, cls, IntPtr.Zero, 0, out var size);
        if (size == 0)
        {
            return null;
        }
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (!Native.GetTokenInformation(token, cls, buf, size, out _))
            {
                return null;
            }
            // TOKEN_USER / TOKEN_APPCONTAINER_INFORMATION start with a PSID.
            return Native.SidToString(Marshal.ReadIntPtr(buf));
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    /// <summary>(user SID, AppContainer SID or "") for a process, or (null, null) if unreadable.</summary>
    public static (string? User, string? Package) ReadToken(int pid)
    {
        var hproc = Native.OpenProcess(Native.ProcessQueryLimitedInformation, false, pid);
        if (hproc == IntPtr.Zero)
        {
            return (null, null);
        }
        try
        {
            if (!Native.OpenProcessToken(hproc, Native.TokenQuery, out var token))
            {
                return (null, null);
            }
            try
            {
                var user = SidFromInfo(token, Native.TokenUser);
                string? package = "";
                var isAc = TokenInfo(token, Native.TokenIsAppContainer);
                if (isAc is not null && BitConverter.ToUInt32(isAc, 0) != 0)
                {
                    package = SidFromInfo(token, Native.TokenAppContainerSid);
                }
                return (user, package);
            }
            finally
            {
                Native.CloseHandle(token);
            }
        }
        finally
        {
            Native.CloseHandle(hproc);
        }
    }

    // ------------------------------------------------------------------ services

    /// <summary>Running Win32 services grouped by PID.</summary>
    public static Dictionary<int, List<string>> ServicesByPid()
    {
        var byPid = new Dictionary<int, List<string>>();
        var scm = Native.OpenSCManager(null, null, Native.ScManagerEnumerateService);
        if (scm == IntPtr.Zero)
        {
            throw new System.ComponentModel.Win32Exception();
        }
        try
        {
            var resume = 0;
            Native.EnumServicesStatusEx(scm, Native.ScEnumProcessInfo, Native.ServiceWin32, Native.ServiceActive, IntPtr.Zero, 0, out var needed, out _, ref resume, null);
            var buf = Marshal.AllocHGlobal(needed + 4096);
            try
            {
                resume = 0;
                if (!Native.EnumServicesStatusEx(scm, Native.ScEnumProcessInfo, Native.ServiceWin32, Native.ServiceActive, buf, needed + 4096, out _, out var count, ref resume, null))
                {
                    throw new System.ComponentModel.Win32Exception();
                }
                var size = Marshal.SizeOf<Native.EnumServiceStatusProcess>();
                for (var i = 0; i < count; i++)
                {
                    var s = Marshal.PtrToStructure<Native.EnumServiceStatusProcess>(buf + i * size);
                    var pid = (int)s.dwProcessId;
                    if (pid == 0)
                    {
                        continue;
                    }
                    if (!byPid.TryGetValue(pid, out var list))
                    {
                        list = [];
                        byPid[pid] = list;
                    }
                    list.Add(Marshal.PtrToStringUni(s.lpServiceName) ?? "");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
        finally
        {
            Native.CloseServiceHandle(scm);
        }
        return byPid;
    }

    /// <summary>The service's start account, from its configuration (lpServiceStartName).</summary>
    internal static string? ServiceStartName(string name)
    {
        var scm = Native.OpenSCManager(null, null, Native.ScManagerConnect);
        if (scm == IntPtr.Zero)
        {
            return null;
        }
        try
        {
            var h = Native.OpenService(scm, name, Native.ServiceQueryConfig);
            if (h == IntPtr.Zero)
            {
                return null;
            }
            try
            {
                Native.QueryServiceConfig(h, IntPtr.Zero, 0, out var needed);
                if (needed == 0)
                {
                    return null;
                }
                var buf = Marshal.AllocHGlobal(needed);
                try
                {
                    if (!Native.QueryServiceConfig(h, buf, needed, out _))
                    {
                        return null;
                    }
                    var cfg = Marshal.PtrToStructure<Native.QueryServiceConfigData>(buf);
                    return Marshal.PtrToStringUni(cfg.lpServiceStartName) ?? "";
                }
                finally
                {
                    Marshal.FreeHGlobal(buf);
                }
            }
            finally
            {
                Native.CloseServiceHandle(h);
            }
        }
        finally
        {
            Native.CloseServiceHandle(scm);
        }
    }

    public static string? ServiceAccountSid(string name)
    {
        var start = ServiceStartName(name);
        if (start is null)
        {
            return null;
        }
        var account = PyStr.Lower(PyStr.Strip(start.Length > 0 ? start : "LocalSystem"));
        return AccountSids.GetValueOrDefault(account);
    }

    // ------------------------------------------------------------------ listeners

    private static Identity ResolveIdentity(int pid, List<string>? services, Dictionary<int, ProcInfo> procs,
        Dictionary<int, List<string>> serviceMap, Dictionary<int, Identity> cache)
    {
        if (cache.TryGetValue(pid, out var cached))
        {
            return cached;
        }
        Identity ident;
        if (pid == 4)
        {
            ident = new Identity("System", "", SystemSid, "");
        }
        else if (pid == 0)
        {
            ident = new Identity("System Idle Process", "", SystemSid, "");
        }
        else
        {
            var exe = ProcessExe(pid);
            var name = exe.Length > 0 ? NtPath.Basename(exe) : procs.TryGetValue(pid, out var p) ? p.Name : "";
            var (user, package) = ReadToken(pid);
            if (user is null && services is { Count: > 0 })
            {
                // Services can't be AppContainers; their account comes from the service config.
                var sids = services.Select(ServiceAccountSid).Where(s => s is not null).Distinct().ToList();
                if (sids.Count == 1)
                {
                    user = sids[0];
                }
                package = "";
            }
            if (user is null && exe.Length > 0 && procs.TryGetValue(pid, out var info))
            {
                // A child of a service process running the same program inherits its account.
                if (serviceMap.TryGetValue(info.ParentPid, out var parentServices) && parentServices.Count > 0
                    && PyStr.Lower(ProcessExe(info.ParentPid)) == PyStr.Lower(exe))
                {
                    var sids = parentServices.Select(ServiceAccountSid).Where(s => s is not null).Distinct().ToList();
                    if (sids.Count == 1)
                    {
                        user = sids[0];
                        package = "";
                    }
                }
            }
            if (user is null && exe.Length > 0)
            {
                var baseName = PyStr.Lower(NtPath.Basename(exe));
                var sysdir = PyStr.Lower(Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "System32"));
                if (AlwaysSystem.Contains(baseName) && PyStr.Lower(NtPath.Dirname(exe)) == sysdir)
                {
                    user = SystemSid;
                    package = "";
                }
            }
            ident = new Identity(name, exe, user, package);
        }
        cache[pid] = ident;
        return ident;
    }

    public static List<Listener> ReadListeners()
    {
        Dictionary<int, List<string>> svcMap;
        var servicesKnown = true;
        try
        {
            svcMap = ServicesByPid();
        }
        catch (Exception)
        {
            svcMap = [];
            servicesKnown = false;
        }
        var procs = ProcessSnapshot();
        var cache = new Dictionary<int, Identity>();
        var output = new List<Listener>();
        var seen = new HashSet<(string, string, int)>();
        foreach (var s in IpHelper.AllSockets())
        {
            if (s.Protocol == "tcp" && s.State != IpHelper.MibTcpStateListen)
            {
                continue;
            }
            if (!seen.Add((s.Protocol, s.LocalIp, s.LocalPort)))
            {
                continue;
            }
            List<string>? services = servicesKnown ? (svcMap.TryGetValue(s.Pid, out var l) ? [.. l] : []) : null;
            if (s.Pid == 4)
            {
                services = [];
            }
            var ident = ResolveIdentity(s.Pid, services, procs, svcMap, cache);
            output.Add(new Listener
            {
                Protocol = s.Protocol,
                Address = s.LocalIp,
                Port = s.LocalPort,
                Pid = s.Pid,
                Process = ident.Name,
                Exe = ident.Exe,
                Services = services,
                UserSid = ident.UserSid,
                PackageSid = ident.PackageSid,
            });
        }
        return output
            .OrderBy(x => x.Protocol, StringComparer.Ordinal)
            .ThenBy(x => x.Port)
            .ThenBy(x => x.Address, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>Established TCP connections (for the usage fact).</summary>
    internal static List<SocketEntry> EstablishedTcp() =>
        IpHelper.AllSockets().Where(s => s.Protocol == "tcp" && s.State == IpHelper.MibTcpStateEstab).ToList();

    // ------------------------------------------------------------------ signatures

    /// <summary>Authenticode status for many files (catalog-aware), keyed by lower-case path.</summary>
    public static Dictionary<string, (string Status, string Signer)> Signatures(IEnumerable<string> paths)
    {
        var output = new Dictionary<string, (string, string)>(StringComparer.Ordinal);
        var unique = paths.Where(p => p.Length > 0).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();
        var results = new (string, string)[unique.Count];
        Parallel.For(0, unique.Count, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(2, Environment.ProcessorCount / 2) }, i =>
        {
            try
            {
                var r = WinTrust.Verify(unique[i]);
                results[i] = (r.Status, r.Signer);
            }
            catch (Exception)
            {
                results[i] = ("Unreadable", "");
            }
        });
        for (var i = 0; i < unique.Count; i++)
        {
            output[PyStr.Lower(unique[i])] = results[i];
        }
        return output;
    }

    /// <summary>'CN=Microsoft Windows, O=Microsoft Corporation, ...' → 'Microsoft Corporation'.</summary>
    public static string Publisher(string signer)
    {
        foreach (var key in new[] { "O", "CN" })
        {
            var m = System.Text.RegularExpressions.Regex.Match(signer, $"(?:^|,\\s*){key}=(\"([^\"]+)\"|[^,]+)");
            if (m.Success)
            {
                return PyStr.Strip(m.Groups[2].Success ? m.Groups[2].Value : m.Groups[1].Value);
            }
        }
        return "";
    }
}
