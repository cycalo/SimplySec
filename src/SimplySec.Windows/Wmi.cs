using System.Management;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using Microsoft.Win32;

namespace SimplySec.Windows;

/// <summary>WMI/CIM through System.Management: the same providers the PowerShell cmdlets used.</summary>
public static class Wmi
{
    public const string Cimv2 = @"root\cimv2";
    public const string StandardCimv2 = @"root\StandardCimv2";
    public const string Defender = @"root\Microsoft\Windows\Defender";
    public const string Smb = @"root\Microsoft\Windows\SMB";
    public const string SecurityCenter = @"root\SecurityCenter2";

    public static List<ManagementBaseObject> Query(string ns, string wql)
    {
        var scope = new ManagementScope(ns);
        scope.Connect();
        using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(wql), new System.Management.EnumerationOptions { ReturnImmediately = true, Rewindable = false });
        var output = new List<ManagementBaseObject>();
        foreach (var o in searcher.Get())
        {
            output.Add(o);
        }
        return output;
    }

    public static ManagementBaseObject? First(string ns, string wql) => Query(ns, wql).FirstOrDefault();

    /// <summary>Call a static (class) method, e.g. MSFT_MpPreference.Set; returns the out-parameters.</summary>
    public static ManagementBaseObject? ClassMethod(string ns, string cls, string method, IDictionary<string, object> args)
    {
        using var mc = new ManagementClass(new ManagementScope(ns), new ManagementPath(cls), null);
        using var inParams = mc.GetMethodParameters(method);
        foreach (var (k, v) in args)
        {
            inParams[k] = v;
        }
        return mc.InvokeMethod(method, inParams, null);
    }

    /// <summary>Call a method on an instance.</summary>
    public static ManagementBaseObject? InstanceMethod(ManagementObject instance, string method, IDictionary<string, object>? args = null)
    {
        using var inParams = instance.GetMethodParameters(method);
        foreach (var (k, v) in args ?? new Dictionary<string, object>())
        {
            inParams![k] = v;
        }
        return instance.InvokeMethod(method, inParams, null);
    }

    public static object? Get(ManagementBaseObject o, string prop)
    {
        try
        {
            return o[prop];
        }
        catch (ManagementException)
        {
            return null;
        }
    }

    /// <summary>A WMI value as JSON the way ConvertTo-Json writes it (numbers, strings, bools, arrays).</summary>
    public static JsonNode? Json(object? v) => v switch
    {
        null => null,
        string s => JsonValue.Create(s),
        bool b => JsonValue.Create(b),
        byte or sbyte or short or ushort or int => JsonValue.Create(Convert.ToInt32(v, System.Globalization.CultureInfo.InvariantCulture)),
        uint u => JsonValue.Create((long)u),
        long l => JsonValue.Create(l),
        ulong ul => JsonValue.Create(ul),
        float or double => JsonValue.Create(Convert.ToDouble(v, System.Globalization.CultureInfo.InvariantCulture)),
        Array a => new JsonArray(a.Cast<object?>().Select(Json).ToArray()),
        _ => JsonValue.Create(v.ToString()),
    };

    public static JsonNode? Prop(ManagementBaseObject o, string prop) => Json(Get(o, prop));

    public static string Str(ManagementBaseObject o, string prop) => Get(o, prop)?.ToString() ?? "";

    public static long Long(ManagementBaseObject o, string prop) =>
        Get(o, prop) is { } v ? Convert.ToInt64(v, System.Globalization.CultureInfo.InvariantCulture) : 0;

    public static bool Bool(ManagementBaseObject o, string prop) => Get(o, prop) is true;

    /// <summary>True when an exception means "run as administrator" (facts.ps1's needs_admin test).</summary>
    public static bool IsAccessDenied(Exception e) =>
        e is UnauthorizedAccessException
        || (e is ManagementException me && me.ErrorCode == ManagementStatus.AccessDenied)
        || (e is COMException ce && ce.HResult == unchecked((int)0x80070005))
        || e.HResult == unchecked((int)0x80070005)
        || e.Message.Contains("0x80070005", StringComparison.OrdinalIgnoreCase)
        || (e.InnerException is { } inner && IsAccessDenied(inner));
}

/// <summary>Registry values as PowerShell's Get-ItemProperty returns them (DWORD as signed Int32).</summary>
public static class PsRegistry
{
    private static RegistryKey? Open(string path)
    {
        var (hive, sub) = path.StartsWith(@"HKCU\", StringComparison.Ordinal)
            ? (RegistryHive.CurrentUser, path[5..])
            : (RegistryHive.LocalMachine, path.StartsWith(@"HKLM\", StringComparison.Ordinal) ? path[5..] : path);
        try
        {
            return RegistryKey.OpenBaseKey(hive, RegistryView.Registry64).OpenSubKey(sub);
        }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    /// <summary>The value, or null when the key or value is missing or unreadable.</summary>
    public static JsonNode? Value(string path, string name)
    {
        using var key = Open(path);
        if (key is null)
        {
            return null;
        }
        try
        {
            return key.GetValue(name) switch
            {
                null => null,
                int i => JsonValue.Create(i),
                long l => JsonValue.Create(l),
                string s => JsonValue.Create(s),
                string[] a => new JsonArray(a.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray()),
                byte[] b => new JsonArray(b.Select(x => (JsonNode?)JsonValue.Create((int)x)).ToArray()),
                var other => JsonValue.Create(other.ToString()),
            };
        }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    public static bool KeyExists(string path)
    {
        using var key = Open(path);
        return key is not null;
    }
}
