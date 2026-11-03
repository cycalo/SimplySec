using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Serilog;
using Serilog.Events;
using SimplySec.Core.Actions;
using SimplySec.Core.Engine;
using SimplySec.Core.Storage;
using SimplySec.Windows.Interop;

namespace SimplySec.Windows;

/// <summary>
/// Where SimplySec keeps its data. The change journal and firewall backups live in an admin-only
/// %ProgramData%\SimplySec; per-user history, settings and logs in %LOCALAPPDATA%\SimplySec.
/// SIMPLYSEC_DATA_DIR / SIMPLYSEC_USER_DIR override both (tests).
/// </summary>
public static class Paths
{
    public static string DataDir =>
        Environment.GetEnvironmentVariable("SIMPLYSEC_DATA_DIR") is { Length: > 0 } d ? d
        : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SimplySec");

    public static string UserDir =>
        Environment.GetEnvironmentVariable("SIMPLYSEC_USER_DIR") is { Length: > 0 } d ? d
        : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SimplySec");

    public static string JournalPath => Path.Combine(DataDir, "simplysec.db");
    public static string HistoryPath => Path.Combine(UserDir, "history.db");
    public static string BackupsDir => Path.Combine(DataDir, "backups");
    public static string LogDir => Path.Combine(UserDir, "logs");
    public static string FactsScript => Path.Combine(AppContext.BaseDirectory, "scripts", "facts.ps1");

    /// <summary>Only SYSTEM and Administrators may change the journal; Users may read it.</summary>
    public const string DataDirSddl = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

    public static void HardenDataDir()
    {
        Directory.CreateDirectory(DataDir);
        var sec = new DirectorySecurity();
        sec.SetSecurityDescriptorSddlForm(DataDirSddl, AccessControlSections.Access | AccessControlSections.Owner);
        new DirectoryInfo(DataDir).SetAccessControl(sec);
    }

    /// <summary>True when only SYSTEM/Administrators/TrustedInstaller own the folder and can write to it.</summary>
    public static bool DataDirIsTrusted()
    {
        var info = new DirectoryInfo(DataDir);
        if (!info.Exists)
        {
            return false;
        }
        var sec = info.GetAccessControl();
        string[] trusted = ["S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"];
        if (sec.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !trusted.Contains(owner.Value))
        {
            return false;
        }
        const FileSystemRights write = FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.ChangePermissions
                                       | FileSystemRights.TakeOwnership | FileSystemRights.Delete;
        foreach (FileSystemAccessRule rule in sec.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow && (rule.FileSystemRights & write) != 0 && !trusted.Contains(rule.IdentityReference.Value))
            {
                return false;
            }
        }
        return true;
    }
}

/// <summary>Administrator checks and elevation (UAC) for the GUI and CLI.</summary>
public static class Elevation
{
    public const string GuiExe = "SimplySec.exe";
    public const string CliExe = "simplysec-cli.exe";

    public static bool IsAdmin() => Native.IsUserAnAdmin();

    /// <summary>The executable and argument string to run SimplySec with these arguments.</summary>
    public static (string Exe, string Args) CommandFor(IReadOnlyList<string> args, bool gui)
    {
        var dir = AppContext.BaseDirectory;
        var sibling = Path.Combine(dir, gui ? GuiExe : CliExe);
        var exe = File.Exists(sibling) ? sibling : Environment.ProcessPath ?? sibling;
        return (exe, ArgLine(args));
    }

    /// <summary>Windows command-line quoting (subprocess.list2cmdline).</summary>
    public static string ArgLine(IEnumerable<string> args) => string.Join(' ', args.Select(Quote));

    private static string Quote(string a)
    {
        if (a.Length > 0 && !a.Any(c => c is ' ' or '\t' or '"'))
        {
            return a;
        }
        var sb = new System.Text.StringBuilder("\"");
        var backslashes = 0;
        foreach (var c in a)
        {
            if (c == '\\')
            {
                backslashes++;
                continue;
            }
            if (c == '"')
            {
                sb.Append('\\', backslashes * 2 + 1).Append('"');
            }
            else
            {
                sb.Append('\\', backslashes).Append(c);
            }
            backslashes = 0;
        }
        sb.Append('\\', backslashes * 2).Append('"');
        return sb.ToString();
    }

    /// <summary>Restart this program as administrator (UAC). False when the user said no.</summary>
    public static bool RelaunchElevated(IReadOnlyList<string> args, bool gui = true)
    {
        var (exe, line) = CommandFor(args, gui);
        try
        {
            Process.Start(new ProcessStartInfo(exe, line) { UseShellExecute = true, Verb = "runas" })?.Dispose();
            return true;
        }
        catch (Win32Exception)
        {
            return false;
        }
    }

    public enum ElevatedStatus
    {
        Finished,
        Declined,
        TimedOut,
    }

    /// <summary>Run the CLI elevated and wait. Declined UAC and timeouts are reported separately from exit codes.</summary>
    public static (ElevatedStatus Status, int ExitCode) RunElevatedAndWait(IReadOnlyList<string> args, TimeSpan? timeout = null)
    {
        var (exe, line) = CommandFor(args, gui: false);
        Process? proc;
        try
        {
            proc = Process.Start(new ProcessStartInfo(exe, line) { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden });
        }
        catch (Win32Exception exc) when (exc.NativeErrorCode == 1223)
        {
            return (ElevatedStatus.Declined, -1);
        }
        catch (Win32Exception)
        {
            return (ElevatedStatus.Declined, -1);
        }
        if (proc is null)
        {
            return (ElevatedStatus.Declined, -1);
        }
        using (proc)
        {
            if (!proc.WaitForExit(timeout ?? TimeSpan.FromMinutes(10)))
            {
                return (ElevatedStatus.TimedOut, -1);
            }
            return (ElevatedStatus.Finished, proc.ExitCode);
        }
    }
}

/// <summary>Rotating log in %LOCALAPPDATA%\SimplySec\logs (1 MB × 3), shared by the GUI and helper.</summary>
public static class Logging
{
    private static bool _done;

    public static void Setup(bool verbose = false)
    {
        if (_done)
        {
            return;
        }
        _done = true;
        try
        {
            Directory.CreateDirectory(Paths.LogDir);
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Is(verbose ? LogEventLevel.Debug : LogEventLevel.Information)
                .WriteTo.File(Path.Combine(Paths.LogDir, "simplysec.log"),
                    outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss,fff} {Level:u7} {SourceContext}: {Message:lj}{NewLine}{Exception}",
                    fileSizeLimitBytes: 1_000_000, rollOnFileSizeLimit: true, retainedFileCountLimit: 4, shared: true,
                    formatProvider: System.Globalization.CultureInfo.InvariantCulture)
                .CreateLogger();
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

/// <summary>Wires the real Windows adapters, collector and stores into a ScanEngine.</summary>
public static class WindowsHost
{
    public static Adapters RealAdapters() => new()
    {
        Firewall = new Firewall(),
        Registry = new RegistryAdapter(),
        Services = new ServicesAdapter(),
        Network = new Network(),
        System = new SystemSetters(),
        Accounts = new AccountsAdapter(),
        Wifi = new Wifi(),
        Scheduler = new Scheduler(),
    };

    public static ScanEngine CreateEngine(Func<Action<string>?, RawScan>? collector = null) => new(new EngineOptions
    {
        Adapters = RealAdapters,
        Journal = readOnly => new Journal(Paths.JournalPath, readOnly),
        History = () => new History(Paths.HistoryPath),
        Collector = collector ?? (progress => Collector.Collect(progress)),
        IsAdmin = Elevation.IsAdmin,
        BackupsDir = Paths.BackupsDir,
        PrepareDataDir = Paths.HardenDataDir,
        FileExists = collector is null ? File.Exists : null,
    });
}
