using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Threading;
using Serilog;
using SimplySec.App.Dialogs;
using SimplySec.App.Infrastructure;
using SimplySec.App.ViewModels;
using SimplySec.App.Views;
using SimplySec.Commands;
using SimplySec.Core.Engine;
using SimplySec.Windows;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;
using Wpf.Ui.Markup;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;

namespace SimplySec.App;

/// <summary>
/// SimplySec.exe. With CLI arguments it runs the command without a window (the elevated helper
/// and the daily-check task use this); otherwise it opens the window. Nothing is scanned until
/// the user clicks "Scan &amp; Protect".
///
/// Developer switch: <c>--load-raw FILE</c> shows a saved raw scan (from <c>scan --raw</c>)
/// instead of scanning, so the UI can be exercised without touching the PC.
/// </summary>
public static partial class Program
{
    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AttachConsole(int processId);

    [STAThread]
    public static int Main(string[] args)
    {
        string? rawFile = null;
        string? snapshotDir = null;
        if (args.Length is 2 or 4 && args[0] == "--load-raw")
        {
            rawFile = args[1];
            if (args.Length == 4 && args[2] == "--snapshot")
            {
                snapshotDir = args[3];
            }
        }
        else if (args.Length == 2 && args[0] == "--snapshot")
        {
            snapshotDir = args[1]; // scan this PC first, then render the pages
        }
        else if (args.Length > 0)
        {
            // Started from a terminal: print there. Started elevated or by the task: no console.
            AttachConsole(-1);
            Console.OutputEncoding = new UTF8Encoding(false);
            return new Cli(new CliHost()).Run(args);
        }
        Logging.Setup();
        var app = new Application { ShutdownMode = ShutdownMode.OnMainWindowClose };
        AddResources(app);
        app.DispatcherUnhandledException += OnUnhandled;

        RawScan? raw = null;
        if (rawFile is not null)
        {
            raw = RawScan.FromJson(JsonNode.Parse(File.ReadAllText(rawFile))!);
        }
        var services = new WindowsAppServices(raw is null ? null : () => WindowsHost.CreateEngine(_ => raw));
        var vm = new MainViewModel(services, new WpfDialogs(), new BackgroundRunner(new DispatcherSynchronizationContext(app.Dispatcher)));
        var window = new MainWindow(vm);
        if (ThemeOverride() is { } forced)
        {
            window.Loaded += (_, _) => ApplicationThemeManager.Apply(forced, WindowBackdropType.Mica, true);
        }
        else
        {
            SystemThemeWatcher.Watch(window);
        }
        if (raw is not null)
        {
            window.Loaded += async (_, _) =>
            {
                window.LoadRaw(raw);
                if (snapshotDir is not null)
                {
                    await Snapshots.TakeAsync(window, snapshotDir);
                    app.Shutdown();
                }
            };
        }
        else if (snapshotDir is not null)
        {
            window.Loaded += (_, _) =>
            {
                vm.Error += _ => app.Shutdown(1);
                vm.StartScan(then: async () =>
                {
                    await Snapshots.TakeAsync(window, snapshotDir);
                    app.Shutdown();
                });
            };
        }
        return app.Run(window);
    }

    /// <summary>Developer override for checking both themes: SIMPLYSEC_THEME=light or dark.</summary>
    private static ApplicationTheme? ThemeOverride() => Environment.GetEnvironmentVariable("SIMPLYSEC_THEME") switch
    {
        "light" => ApplicationTheme.Light,
        "dark" => ApplicationTheme.Dark,
        _ => null,
    };

    /// <summary>WPF-UI's theme and control styles; the theme follows Windows and switches live.</summary>
    public static void AddResources(Application app)
    {
        var theme = ThemeOverride() ?? (ApplicationThemeManager.GetSystemTheme() == SystemTheme.Dark ? ApplicationTheme.Dark : ApplicationTheme.Light);
        app.Resources.MergedDictionaries.Add(new ThemesDictionary { Theme = theme });
        app.Resources.MergedDictionaries.Add(new ControlsDictionary());
    }

    private static void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Log.Error(e.Exception, "unhandled error in the window");
        MessageBox.Show(Application.Current?.MainWindow!, $"Something went wrong: {e.Exception.Message}\n\nDetails are in {Paths.LogDir}.", "SimplySec",
            MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true;
    }
}
