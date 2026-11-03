using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Imaging;
using SimplySec.App.Controls;
using SimplySec.App.Infrastructure;
using SimplySec.App.Theme;
using SimplySec.App.ViewModels;
using SimplySec.Core.Engine;
using Wpf.Ui.Abstractions;
using Wpf.Ui.Controls;
using static SimplySec.App.Theme.Ui;

namespace SimplySec.App.Views;

/// <summary>Navigation on the left, progress and pages on the right, status at the bottom (port of main_window.py).</summary>
public sealed class MainWindow : FluentWindow
{
    private sealed class PageProvider(Dictionary<Type, PageView> pages) : INavigationViewPageProvider
    {
        public object? GetPage(Type pageType) => pages.GetValueOrDefault(pageType);
    }

    public MainViewModel Vm { get; }
    public NavigationView Nav { get; }
    public ProgressPanel Progress { get; } = new();
    public System.Windows.Controls.TextBlock Status { get; } = Text("", TextStyle.Dim, wrap: false);

    /// <summary>The pages in navigation order (v2's MainWindow.pages).</summary>
    public List<(string Name, PageView Page)> Pages { get; } = [];

    public MainWindow(MainViewModel vm)
    {
        Vm = vm;
        var admin = vm.IsAdmin;
        Title = $"SimplySec {AppInfo.Version}" + (admin ? "" : " (read-only)");
        Width = 1180;
        Height = 800;
        MinWidth = 900;
        MinHeight = 600;
        ExtendsContentIntoTitleBar = true;
        WindowBackdropType = WindowBackdropType.Mica;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        try
        {
            Icon = BitmapFrame.Create(new Uri("pack://application:,,,/simplysec.ico"));
        }
        catch (Exception)
        {
            // Not fatal (e.g. in tests, where the resource assembly is not the entry assembly).
        }

        var settings = new SettingsPage(vm);
        settings.RestartRequested += RestartAsAdmin;
        Add("Overview", SymbolRegular.Home24, new OverviewPage(vm));
        Add("This PC", SymbolRegular.Desktop24, new ThisPcPage(vm));
        Add("Open ports", SymbolRegular.PlugConnected24, new PortsPage(vm));
        Add("My network", SymbolRegular.Router24, new NetworkPage(vm));
        Add("History", SymbolRegular.History24, new HistoryPage(vm));
        Add("Changes", SymbolRegular.ArrowUndo24, new ChangesPage(vm));
        Add("Settings", SymbolRegular.Settings24, settings);

        Nav = new NavigationView
        {
            PaneDisplayMode = NavigationViewPaneDisplayMode.Left,
            IsBackButtonVisible = NavigationViewBackButtonVisible.Collapsed,
            IsPaneToggleVisible = false,
            OpenPaneLength = 220,
            PaneFooter = ModeBadge(admin),
            Header = new Border { Child = Progress, Margin = new Thickness(28, 12, 28, 0) },
        };
        foreach (var (name, page) in Pages)
        {
            Nav.MenuItems.Add(new NavigationViewItem
            {
                Content = name,
                Icon = new SymbolIcon { Symbol = (SymbolRegular)page.Tag! },
                TargetPageType = page.GetType(),
            });
        }
        Nav.SetPageProviderService(new PageProvider(Pages.ToDictionary(p => p.Page.GetType(), p => p.Page)));

        var root = new DockPanel { LastChildFill = true };
        var bar = new TitleBar { Title = Title };
        DockPanel.SetDock(bar, Dock.Top);
        root.Children.Add(bar);
        Status.Margin = new Thickness(28, 6, 28, 8);
        DockPanel.SetDock(Status, Dock.Bottom);
        root.Children.Add(Status);
        root.Children.Add(Nav);
        Content = root;

        vm.BusyChanged += OnBusy;
        vm.Progress += OnProgress;
        vm.Error += OnError;
        vm.ScanFinished += r => Status.Text = string.Create(System.Globalization.CultureInfo.InvariantCulture, $"Scan finished in {r.Duration:0} s.");
        Loaded += (_, _) => Go("Overview");
        // Theme brushes update by themselves; colours chosen in code (severity text, impact,
        // the ring) are rebuilt by showing the current result again.
        Wpf.Ui.Appearance.ApplicationThemeManager.Changed += (_, _) => Dispatcher.BeginInvoke(() =>
        {
            if (Vm.Result is { } r && !Vm.IsBusy)
            {
                Vm.Publish(r);
            }
        });
    }

    private void Add(string name, SymbolRegular icon, PageView page)
    {
        page.Tag = icon;
        Pages.Add((name, page));
    }

    public PageView Page(string name) => Pages.First(p => p.Name == name).Page;

    public void Go(string name)
    {
        if (Pages.FirstOrDefault(p => p.Name == name) is { Page: { } page })
        {
            Nav.Navigate(page.GetType());
        }
    }

    /// <summary>Bottom-left: a coloured mode pill, and "Restart as administrator" when needed.</summary>
    private StackPanel ModeBadge(bool admin)
    {
        var box = VStack(6);
        box.Margin = new Thickness(14, 8, 14, 14);
        var pill = Chip(admin ? "Administrator mode" : "Read-only mode", Palette.Brush(admin ? Palette.Good : Palette.Amber));
        pill.CornerRadius = new CornerRadius(10);
        pill.Padding = new Thickness(10, 4, 10, 4);
        pill.HorizontalAlignment = HorizontalAlignment.Left;
        pill.ToolTip = admin
            ? "Fixes and undo apply directly."
            : "Scans work fully. Applying or undoing a fix asks Windows for permission each time.";
        box.Children.Add(pill);
        if (!admin)
        {
            box.Children.Add(Text("Fixes ask for permission", TextStyle.Dim));
            box.Children.Add(Button("Restart as administrator", RestartAsAdmin));
        }
        return box;
    }

    public void RestartAsAdmin()
    {
        if (Vm.IsBusy)
        {
            Vm.Dialogs.Info("Busy", "Wait for the current task to finish first.");
            return;
        }
        if (Vm.Services.RelaunchElevated())
        {
            Application.Current.Shutdown();
        }
        else
        {
            Vm.Dialogs.Info("Not restarted", "Administrator permission was not given.");
        }
    }

    private void OnBusy(bool busy, string text)
    {
        if (busy)
        {
            Progress.Start(text.Length > 0 ? text : "Working…", Vm.TaskSteps);
            Status.Text = text;
        }
        else
        {
            Progress.Finish();
        }
    }

    private void OnProgress(string text)
    {
        Progress.UpdateText(text);
        if (!SimplySec.Core.Engine.Progress.IsDone(text))
        {
            Status.Text = text;
        }
    }

    private void OnError(string text)
    {
        Status.Text = text;
        Vm.Dialogs.Warn("SimplySec", text);
    }

    /// <summary>Analyse a saved raw scan (developer switch --load-raw) and show it.</summary>
    public void LoadRaw(RawScan raw)
    {
        var (result, ctx) = Analysis.AnalyzeWithContext(raw);
        Vm.Engine.SetLast(raw, result, ctx);
        Vm.Publish(result);
    }
}
