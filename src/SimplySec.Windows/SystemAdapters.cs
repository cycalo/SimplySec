using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using Microsoft.Win32;
using SimplySec.Core.Actions;
using SimplySec.Core.Compat;
using SimplySec.Windows.Interop;

namespace SimplySec.Windows;

public sealed class RegistryException(string message) : Exception(message);

/// <summary>Registry values (HKLM/HKCU, 64-bit view). Snapshots are the journal's exact "before" dicts.</summary>
public sealed class RegistryAdapter : IRegistryAdapter
{
    private static readonly Dictionary<string, RegistryValueKind> Types = new(StringComparer.Ordinal)
    {
        ["REG_DWORD"] = RegistryValueKind.DWord,
        ["REG_QWORD"] = RegistryValueKind.QWord,
        ["REG_SZ"] = RegistryValueKind.String,
        ["REG_EXPAND_SZ"] = RegistryValueKind.ExpandString,
        ["REG_MULTI_SZ"] = RegistryValueKind.MultiString,
    };

    private static (RegistryKey Root, string Sub) Split(string path)
    {
        var p = path.Replace('/', '\\');
        var slash = p.IndexOf('\\');
        var hive = PyStr.Upper(slash >= 0 ? p[..slash] : p);
        var sub = slash >= 0 ? p[(slash + 1)..] : "";
        RegistryHive h = hive switch
        {
            "HKLM" or "HKEY_LOCAL_MACHINE" => RegistryHive.LocalMachine,
            "HKCU" or "HKEY_CURRENT_USER" => RegistryHive.CurrentUser,
            _ => throw new RegistryException($"unsupported hive in '{path}'"),
        };
        return (RegistryKey.OpenBaseKey(h, RegistryView.Registry64), sub);
    }

    public RegSnapshot Read(string path, string name)
    {
        var (root, sub) = Split(path);
        using (root)
        {
            using var key = root.OpenSubKey(sub);
            if (key is null)
            {
                return new RegSnapshot(false, false, null, null);
            }
            var value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (value is null)
            {
                return new RegSnapshot(true, false, null, null);
            }
            var kind = key.GetValueKind(name);
            var typeName = Types.FirstOrDefault(kv => kv.Value == kind).Key ?? ((int)kind).ToString(System.Globalization.CultureInfo.InvariantCulture);
            JsonNode? json = value switch
            {
                int i when kind == RegistryValueKind.DWord => JsonValue.Create(unchecked((uint)i)),
                long l when kind == RegistryValueKind.QWord => JsonValue.Create(unchecked((ulong)l)),
                string s => JsonValue.Create(s),
                string[] arr => Js.StrArray(arr),
                byte[] bytes => JsonValue.Create(Convert.ToBase64String(bytes)),
                _ => JsonValue.Create(value.ToString()),
            };
            return new RegSnapshot(true, true, typeName, json);
        }
    }

    public void Write(string path, string name, JsonNode? value, string vtype)
    {
        if (!Types.TryGetValue(vtype, out var kind))
        {
            throw new RegistryException($"unsupported registry type {vtype}");
        }
        var (root, sub) = Split(path);
        using (root)
        {
            try
            {
                using var key = root.CreateSubKey(sub, writable: true);
                object data = kind switch
                {
                    RegistryValueKind.DWord => unchecked((int)(uint)Js.Long(value)),
                    RegistryValueKind.QWord => unchecked((long)(ulong)Js.Long(value)),
                    RegistryValueKind.MultiString => Js.StrList(value).ToArray(),
                    _ => Js.Str(value),
                };
                key.SetValue(name, data, kind);
            }
            catch (UnauthorizedAccessException)
            {
                throw new RegistryException($"access denied writing {path}\\{name} (administrator rights are needed)");
            }
            catch (System.Security.SecurityException)
            {
                throw new RegistryException($"access denied writing {path}\\{name} (administrator rights are needed)");
            }
        }
    }

    private static void DeleteValue(string path, string name)
    {
        var (root, sub) = Split(path);
        using (root)
        {
            try
            {
                using var key = root.OpenSubKey(sub, writable: true);
                key?.DeleteValue(name, throwOnMissingValue: false);
            }
            catch (UnauthorizedAccessException)
            {
                throw new RegistryException($"access denied deleting {path}\\{name}");
            }
        }
    }

    /// <summary>Delete a key we created, but only if nothing else was put in it since.</summary>
    private static bool DeleteKeyIfEmpty(string path)
    {
        var (root, sub) = Split(path);
        using (root)
        {
            using (var key = root.OpenSubKey(sub))
            {
                if (key is null)
                {
                    return true;
                }
                if (key.SubKeyCount > 0 || key.ValueCount > 0)
                {
                    return false;
                }
            }
            try
            {
                root.DeleteSubKey(sub, throwOnMissingSubKey: false);
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                throw new RegistryException($"access denied deleting key {path}");
            }
        }
    }

    public void Restore(string path, string name, JsonObject before)
    {
        if (Js.Truthy(before["exists"]))
        {
            Write(path, name, before["value"], Js.Str(before["type"]));
            return;
        }
        DeleteValue(path, name);
        if (!Js.Truthy(before["key_existed"]))
        {
            DeleteKeyIfEmpty(path);
        }
    }
}

/// <summary>Windows services: start type and state (allow-listed services only).</summary>
public sealed class ServicesAdapter : IServicesAdapter
{
    private static readonly string[] StartTypes = ["boot", "system", "auto", "manual", "disabled"];

    public ServiceState Get(string name)
    {
        var scm = Native.OpenSCManager(null, null, Native.ScManagerConnect);
        if (scm == IntPtr.Zero)
        {
            throw new System.ComponentModel.Win32Exception();
        }
        try
        {
            var h = Native.OpenService(scm, name, Native.ServiceQueryConfig | Native.ServiceQueryStatus);
            if (h == IntPtr.Zero)
            {
                return new ServiceState(name, false, null, false, false);
            }
            try
            {
                Native.QueryServiceConfig(h, IntPtr.Zero, 0, out var needed);
                var buf = Marshal.AllocHGlobal(Math.Max(needed, 64));
                string startType;
                try
                {
                    if (!Native.QueryServiceConfig(h, buf, needed, out _))
                    {
                        throw new System.ComponentModel.Win32Exception();
                    }
                    var cfg = Marshal.PtrToStructure<Native.QueryServiceConfigData>(buf);
                    startType = cfg.dwStartType < StartTypes.Length ? StartTypes[cfg.dwStartType] : cfg.dwStartType.ToString(System.Globalization.CultureInfo.InvariantCulture);
                }
                finally
                {
                    Marshal.FreeHGlobal(buf);
                }
                Native.QueryServiceStatusEx(h, 0, out var status, Marshal.SizeOf<Native.ServiceStatusProcess>(), out _);
                var delayed = false;
                var dbuf = Marshal.AllocHGlobal(16);
                try
                {
                    if (Native.QueryServiceConfig2(h, Native.ServiceConfigDelayedAutoStartInfo, dbuf, 16, out _))
                    {
                        delayed = Marshal.ReadInt32(dbuf) != 0;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(dbuf);
                }
                return new ServiceState(name, true, startType, delayed, status.dwCurrentState == 4);
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

    public void SetStartType(string name, string startType, bool delayed = false)
    {
        var code = Array.IndexOf(StartTypes, startType);
        if (code < 2)
        {
            throw new ArgumentException($"unsupported start type {startType}");
        }
        var scm = Native.OpenSCManager(null, null, Native.ScManagerConnect);
        try
        {
            var h = Native.OpenService(scm, name, Native.ServiceChangeConfig | Native.ServiceQueryConfig);
            if (h == IntPtr.Zero)
            {
                throw new System.ComponentModel.Win32Exception();
            }
            try
            {
                if (!Native.ChangeServiceConfig(h, Native.ServiceNoChange, (uint)code, Native.ServiceNoChange, null, null, IntPtr.Zero, null, null, null, null))
                {
                    throw new System.ComponentModel.Win32Exception();
                }
                if (startType == "auto")
                {
                    var flag = delayed ? 1 : 0;
                    Native.ChangeServiceConfig2(h, Native.ServiceConfigDelayedAutoStartInfo, ref flag);
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

    public void Start(string name)
    {
        using var sc = new System.ServiceProcess.ServiceController(name);
        sc.Start();
        sc.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
    }

    public void Stop(string name)
    {
        using var sc = new System.ServiceProcess.ServiceController(name);
        sc.Stop();
        sc.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
    }
}

/// <summary>Local accounts, found by RID so localized names never matter.</summary>
public sealed partial class AccountsAdapter : IAccountsAdapter
{
    private const uint UfAccountDisable = 0x2;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct UserInfo20
    {
        public IntPtr usri20_name;
        public IntPtr usri20_full_name;
        public IntPtr usri20_comment;
        public uint usri20_flags;
        public uint usri20_user_id;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserEnum(string? server, int level, int filter, out IntPtr buf, int prefMax, out int read, out int total, ref int resume);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserGetInfo(string? server, string user, int level, out IntPtr buf);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserSetInfo(string? server, string user, int level, ref uint info, out int parmErr);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buf);

    public AccountInfo? FindByRid(int rid)
    {
        var resume = 0;
        if (NetUserEnum(null, 20, 0x2, out var buf, -1, out var read, out _, ref resume) != 0)
        {
            throw new System.ComponentModel.Win32Exception();
        }
        try
        {
            var size = Marshal.SizeOf<UserInfo20>();
            for (var i = 0; i < read; i++)
            {
                var u = Marshal.PtrToStructure<UserInfo20>(buf + i * size);
                if (u.usri20_user_id == rid)
                {
                    return new AccountInfo(Marshal.PtrToStringUni(u.usri20_name) ?? "", (u.usri20_flags & UfAccountDisable) == 0);
                }
            }
        }
        finally
        {
            NetApiBufferFree(buf);
        }
        return null;
    }

    public void SetEnabled(string name, bool enabled)
    {
        // USER_INFO_1 layout: name, password, password_age, priv, home_dir, comment, flags, script_path.
        if (NetUserGetInfo(null, name, 1, out var buf) != 0)
        {
            throw new System.ComponentModel.Win32Exception();
        }
        uint flags;
        try
        {
            flags = (uint)Marshal.ReadInt32(buf, IntPtr.Size * 2 + 8 + IntPtr.Size * 2);
        }
        finally
        {
            NetApiBufferFree(buf);
        }
        flags = enabled ? flags & ~UfAccountDisable : flags | UfAccountDisable;
        var rc = NetUserSetInfo(null, name, 1008, ref flags, out _);
        if (rc != 0)
        {
            throw new System.ComponentModel.Win32Exception(rc);
        }
    }
}
