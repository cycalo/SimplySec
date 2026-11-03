using System.Diagnostics;
using SimplySec.Core.Checks;
using SimplySec.Core.Engine;
using SimplySec.Core.Lan;
using SimplySec.Core.Model;
using SimplySec.Windows;

namespace SimplySec.App.Infrastructure;

/// <summary>Outcome of running the elevated helper (simplysec fix/undo/monitor).</summary>
public enum ElevatedOutcome
{
    Finished,
    Declined,
    TimedOut,
}

/// <summary>Everything the app needs from Windows; tests replace it.</summary>
public interface IAppServices
{
    bool IsAdmin { get; }
    string JournalPath { get; }
    string BackupsDir { get; }
    string DataDir { get; }
    string UserDir { get; }
    string LogDir { get; }
    ScanEngine CreateEngine();
    ILanHost Lan();
    (ElevatedOutcome Outcome, int ExitCode) RunElevated(IReadOnlyList<string> args);
    /// <summary>Restart the app as administrator; false when UAC was declined.</summary>
    bool RelaunchElevated();
    void OpenPath(string path);
    void OpenSettings(string target);
    void WriteReport(string path, ScanResult result, ScanEngine engine);
}

public sealed class WindowsAppServices(Func<ScanEngine>? engine = null) : IAppServices
{
    public bool IsAdmin => Elevation.IsAdmin();
    public string JournalPath => Paths.JournalPath;
    public string BackupsDir => Paths.BackupsDir;
    public string DataDir => Paths.DataDir;
    public string UserDir => Paths.UserDir;
    public string LogDir => Paths.LogDir;

    public ScanEngine CreateEngine() => engine?.Invoke() ?? WindowsHost.CreateEngine();

    public ILanHost Lan() => new WindowsLanHost();

    public (ElevatedOutcome Outcome, int ExitCode) RunElevated(IReadOnlyList<string> args)
    {
        var (status, code) = Elevation.RunElevatedAndWait(args);
        return status switch
        {
            Elevation.ElevatedStatus.Finished => (ElevatedOutcome.Finished, code),
            Elevation.ElevatedStatus.TimedOut => (ElevatedOutcome.TimedOut, code),
            _ => (ElevatedOutcome.Declined, code),
        };
    }

    public bool RelaunchElevated() => Elevation.RelaunchElevated([], gui: true);

    public void OpenPath(string path) =>
        Process.Start(new ProcessStartInfo(path) { UseShellExecute = true })?.Dispose();

    public void OpenSettings(string target) => SystemSetters.OpenSettings(target);

    public void WriteReport(string path, ScanResult result, ScanEngine engine) =>
        Commands.Cli.WriteReport(path, result, engine, Paths.JournalPath);
}

/// <summary>One applied change as shown in the result dialog.</summary>
public sealed record ResultLine(string Summary, string Status, bool? Verified, string Error = "");

/// <summary>What the user chose in the preview dialog.</summary>
public sealed record PreviewChoice(bool Accepted, bool RestorePoint, List<FixWarning> Extra, List<int> Included);

/// <summary>Everything the result dialog shows after applying changes.</summary>
public sealed record ResultSummary(
    List<ResultLine> Lines,
    Dictionary<string, bool> Resolved,
    Dictionary<string, string> Titles,
    int? ScoreBefore,
    int? ScoreAfter,
    List<string> Warnings);

/// <summary>Modal dialogs the view model opens; tests replace it.</summary>
public interface IDialogs
{
    void Info(string title, string text);
    void Warn(string title, string text);
    bool Ask(string title, string text);
    PreviewChoice Preview(Plan plan, bool isAdmin, IReadOnlyDictionary<string, Finding> findings);
    void Results(ResultSummary summary);
    string? SaveFile(string title, string defaultPath, string filter);
}
