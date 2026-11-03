using System.Collections.Concurrent;
using System.Windows;
using System.Windows.Threading;
using SimplySec.App.Infrastructure;
using SimplySec.Commands;
using SimplySec.Core.Engine;
using SimplySec.Core.Lan;
using SimplySec.Core.Model;
using SimplySec.Core.Tests.Support;

namespace SimplySec.App.Tests;

/// <summary>A UI-thread stand-in: posted callbacks queue up until the test pumps them.</summary>
public sealed class PumpContext : SynchronizationContext
{
    private readonly BlockingCollection<(SendOrPostCallback, object?)> _queue = [];

    public override void Post(SendOrPostCallback d, object? state) => _queue.Add((d, state));

    /// <summary>Run queued callbacks on this thread until <paramref name="done"/> or the timeout.</summary>
    public void PumpUntil(Func<bool> done, int timeoutMs = 20000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (!done())
        {
            var left = deadline - DateTime.UtcNow;
            if (left <= TimeSpan.Zero)
            {
                throw new TimeoutException("UI callbacks did not finish in time");
            }
            if (_queue.TryTake(out var item, left < TimeSpan.FromMilliseconds(100) ? left : TimeSpan.FromMilliseconds(100)))
            {
                item.Item1(item.Item2);
            }
        }
    }
}

/// <summary>Records what the view model asks the user, and answers as told.</summary>
public sealed class FakeDialogs : IDialogs
{
    public List<string> Shown { get; } = [];
    public bool AskAnswer { get; set; } = true;
    public Func<PreviewChoice>? PreviewAnswer { get; set; }
    public List<ResultSummary> Summaries { get; } = [];
    public PreviewChoice? LastPreviewDefault { get; private set; }

    public void Info(string title, string text) => Shown.Add($"info {title}: {text}");
    public void Warn(string title, string text) => Shown.Add($"warn {title}: {text}");

    public bool Ask(string title, string text)
    {
        Shown.Add($"ask {title}: {text}");
        return AskAnswer;
    }

    public PreviewChoice Preview(Plan plan, bool isAdmin, IReadOnlyDictionary<string, Finding> findings)
    {
        var model = new ViewModels.PreviewModel(plan, isAdmin, findings);
        LastPreviewDefault = model.Choice(accepted: true);
        Shown.Add($"preview {plan.Items.Count}");
        return PreviewAnswer?.Invoke() ?? LastPreviewDefault;
    }

    public void Results(ResultSummary summary) => Summaries.Add(summary);

    public string? SaveFile(string title, string defaultPath, string filter) => null;
}

/// <summary>App services on fakes: the engine from TestEngines, elevation through the real CLI.</summary>
public sealed class FakeServices(TempDir tmp, ScanEngine engine, bool admin) : IAppServices
{
    public bool IsAdmin { get; set; } = admin;
    public string JournalPath => tmp.File("data/simplysec.db");
    public string BackupsDir => tmp.File("backups");
    public string DataDir => tmp.File("data");
    public string UserDir => tmp.File("user");
    public string LogDir => tmp.File("logs");
    public List<List<string>> Elevated { get; } = [];
    public ElevatedOutcome Outcome { get; set; } = ElevatedOutcome.Finished;

    /// <summary>What the elevated helper runs: the CLI with an administrator engine on the same journal.</summary>
    public Func<ScanEngine>? ElevatedEngine { get; set; }

    public ScanEngine CreateEngine() => engine;
    public ILanHost Lan() => throw new InvalidOperationException("no network in tests");

    public (ElevatedOutcome Outcome, int ExitCode) RunElevated(IReadOnlyList<string> args)
    {
        Elevated.Add([.. args]);
        if (Outcome != ElevatedOutcome.Finished)
        {
            return (Outcome, -1);
        }
        if (ElevatedEngine is null)
        {
            return (ElevatedOutcome.Finished, 0);
        }
        using var output = new StringWriter();
        var code = new Cli(new CliHost
        {
            Engine = ElevatedEngine,
            IsAdmin = () => true,
            Out = output,
            Err = output,
            JournalPath = () => JournalPath,
            ReadLine = () => null,
            Notify = (_, _) => true,
        }).Run([.. args]);
        return (ElevatedOutcome.Finished, code);
    }

    public bool RelaunchElevated() => false;
    public List<string> Opened { get; } = [];
    public void OpenPath(string path) => Opened.Add(path);
    public void OpenSettings(string target) => Opened.Add(target);
    public void WriteReport(string path, ScanResult result, ScanEngine engine) => File.WriteAllText(path, "report");
    public (DailyCheck.TaskAction Task, bool Elsewhere)? ScheduledTask { get; set; }
    public (DailyCheck.TaskAction Task, bool Elsewhere)? DailyTask(ScanEngine engine) => ScheduledTask;
}

/// <summary>One STA thread with a running dispatcher and the app's resources, shared by the window tests.</summary>
public static class UiThread
{
    private static readonly Lazy<Dispatcher> Instance = new(Start);

    private static Dispatcher Start()
    {
        Dispatcher? dispatcher = null;
        using var ready = new ManualResetEventSlim();
        var thread = new Thread(() =>
        {
            var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
            Program.AddResources(app);
            dispatcher = Dispatcher.CurrentDispatcher;
            ready.Set();
            Dispatcher.Run();
        })
        {
            IsBackground = true,
        };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        ready.Wait();
        return dispatcher!;
    }

    public static Dispatcher Dispatcher => Instance.Value;

    public static T Run<T>(Func<T> work) => Dispatcher.Invoke(work);

    public static void Run(Action work) => Dispatcher.Invoke(work);

    /// <summary>Let layout and queued work run (call from inside <see cref="Run"/>).</summary>
    public static void DoEvents()
    {
        var frame = new DispatcherFrame();
        Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, () => frame.Continue = false);
        Dispatcher.PushFrame(frame);
    }
}
