using SimplySec.App.Infrastructure;
using SimplySec.App.ViewModels;
using SimplySec.App.Views;
using SimplySec.Core.Engine;
using SimplySec.Core.Tests.Support;

namespace SimplySec.App.Tests;

public class BackgroundRunnerTests
{
    [Fact]
    public void BackgroundTasksAlwaysFinish()
    {
        // The busy state must always clear: "finished" runs once per task, right before the result.
        var ui = new PumpContext();
        var runner = new BackgroundRunner(ui);
        var events = new List<string>();
        for (var i = 0; i < 25; i++)
        {
            var fails = i % 5 == 0;
            runner.Run<int>(
                progress =>
                {
                    progress("working");
                    return fails ? throw new InvalidOperationException("x") : 1;
                },
                onResult: _ => events.Add("result"),
                onError: _ => events.Add("error"),
                onFinished: () => events.Add("finished"));
        }
        ui.PumpUntil(() => events.Count(e => e == "finished") == 25 && runner.Running == 0, 10000);
        Assert.Equal(20, events.Count(e => e == "result"));
        Assert.Equal(5, events.Count(e => e == "error"));
        for (var i = 0; i < events.Count; i += 2)
        {
            Assert.Equal("finished", events[i]);
            Assert.NotEqual("finished", events[i + 1]);
        }
    }

    [Fact]
    public void ProgressArrivesOnTheUiContext()
    {
        var ui = new PumpContext();
        var runner = new BackgroundRunner(ui);
        var seen = new List<(string, int)>();
        var done = false;
        var uiThread = Environment.CurrentManagedThreadId;
        runner.Run(p =>
        {
            p("one");
            p("two");
            return 0;
        }, onResult: _ => done = true, onProgress: t => seen.Add((t, Environment.CurrentManagedThreadId)));
        ui.PumpUntil(() => done);
        Assert.Equal([("one", uiThread), ("two", uiThread)], seen);
    }
}

/// <summary>The real window on a real scan result (port of test_gui_smoke's page test).</summary>
public sealed class WindowTests : IDisposable
{
    private readonly TempDir _tmp = new();

    public void Dispose() => _tmp.Dispose();

    [Fact]
    public void PagesRender()
    {
        var raw = RawScan.FromJson(Golden.Fixture("this_pc_raw.json"));
        var (engine, _) = TestEngines.Make(_tmp, false, raw);
        UiThread.Run(() =>
        {
            var vm = new MainViewModel(new FakeServices(_tmp, engine, false), new FakeDialogs(),
                new BackgroundRunner(new System.Windows.Threading.DispatcherSynchronizationContext(UiThread.Dispatcher)));
            var window = new MainWindow(vm) { Left = -20000, Top = -20000, ShowActivated = false, ShowInTaskbar = false };
            window.Show();
            try
            {
                UiThread.DoEvents();
                window.LoadRaw(raw);
                foreach (var (name, _) in window.Pages)
                {
                    window.Go(name);
                    UiThread.DoEvents();
                }
                var ports = (PortsPage)window.Page("Open ports");
                Assert.True(ports.Rows.Count > 20);
                Assert.True(ports.VisibleCount < ports.Rows.Count); // "reachable only" filter is on
                var overview = (OverviewPage)window.Page("Overview");
                Assert.Equal(vm.Result!.Score, overview.Ring.Score);
                var thisPc = (ThisPcPage)window.Page("This PC");
                Assert.Equal(vm.Result.Findings.Count(f => f.Scored), thisPc.Cards.Count);
                Assert.Equal(7, window.Nav.MenuItems.Count);
            }
            finally
            {
                window.Close();
            }
        });
    }

    private static void PumpUntil(Func<bool> done)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (!done() && DateTime.UtcNow < deadline)
        {
            UiThread.DoEvents();
            Thread.Sleep(10);
        }
    }

    [Fact]
    public void SettingsOffersToRepointAnOlderDailyCheck()
    {
        var (engine, _) = TestEngines.Make(_tmp, false);
        var old = new DailyCheck.TaskAction("C:/Old/SimplySec/SimplySec.exe", "monitor --run", "07:05");
        var services = new FakeServices(_tmp, engine, false) { ScheduledTask = (old, true) };
        UiThread.Run(() =>
        {
            var vm = new MainViewModel(services, new FakeDialogs(),
                new BackgroundRunner(new System.Windows.Threading.DispatcherSynchronizationContext(UiThread.Dispatcher)));
            var page = new SettingsPage(vm);
            PumpUntil(() => page.RepointOffered);
            Assert.True(page.RepointOffered);

            page.Repoint();
            PumpUntil(() => services.Elevated.Count > 0 && !vm.IsBusy);
            Assert.Equal(["monitor", "--enable", "07:05"], services.Elevated.Single());

            services.ScheduledTask = (old, false);
            page.Refresh();
            PumpUntil(() => !page.RepointOffered);
            Assert.False(page.RepointOffered);
        });
    }

    [Fact]
    public void MouseWheelScrollsThePage()
    {
        var raw = RawScan.FromJson(Golden.Fixture("this_pc_raw.json"));
        var (engine, _) = TestEngines.Make(_tmp, false, raw);
        UiThread.Run(() =>
        {
            var vm = new MainViewModel(new FakeServices(_tmp, engine, false), new FakeDialogs(),
                new BackgroundRunner(new System.Windows.Threading.DispatcherSynchronizationContext(UiThread.Dispatcher)));
            var window = new MainWindow(vm) { Left = -20000, Top = -20000, ShowActivated = false, ShowInTaskbar = false };
            window.Show();
            try
            {
                UiThread.DoEvents();
                window.LoadRaw(raw);
                window.Go("This PC");
                UiThread.DoEvents();
                var page = (ThisPcPage)window.Page("This PC");
                var card = page.Cards.Values.First();
                // Find the scroll viewer that really moves (the page's own or NavigationView's).
                double Offset()
                {
                    double total = page.Scroller.VerticalOffset;
                    for (var d = System.Windows.Media.VisualTreeHelper.GetParent(page); d is not null; d = System.Windows.Media.VisualTreeHelper.GetParent(d))
                    {
                        if (d is System.Windows.Controls.ScrollViewer s)
                        {
                            total += s.VerticalOffset;
                        }
                    }
                    return total;
                }
                var before = Offset();
                var wheel = new System.Windows.Input.MouseWheelEventArgs(System.Windows.Input.Mouse.PrimaryDevice, 0, -120)
                {
                    RoutedEvent = System.Windows.UIElement.PreviewMouseWheelEvent,
                    Source = card,
                };
                card.RaiseEvent(wheel);
                UiThread.DoEvents();
                Assert.True(wheel.Handled);
                Assert.True(Offset() > before, "the page did not scroll");
            }
            finally
            {
                window.Close();
            }
        });
    }

    [Fact]
    public void ChangesPageUndoesSeveralBatches()
    {
        var raw = RawScan.FromJson(Golden.Fixture("this_pc_raw.json"));
        var (engine, adapters) = TestEngines.Make(_tmp, true, raw);
        ((FakeRegistry)adapters.Registry).Values[(@"HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp")] = ("REG_DWORD", 1);
        engine.Scan(save: false);
        // Two batches: the same fix twice gives two journal batches with one change each.
        engine.Apply(engine.Plan([new Selection("rdp.remote_assistance_off")]));
        engine.Apply(engine.Plan([new Selection("rdp.remote_assistance_off")]));
        UiThread.Run(() =>
        {
            var vm = new MainViewModel(new FakeServices(_tmp, engine, true), new FakeDialogs(),
                new BackgroundRunner(new System.Windows.Threading.DispatcherSynchronizationContext(UiThread.Dispatcher)));
            var page = new ChangesPage(vm);
            var rows = (List<ChangeRowView>)page.Table.ItemsSource;
            Assert.Equal(2, page.Active);
            Assert.Equal(2, rows.Count(r => r.IsBatch));
            foreach (var r in rows.Where(r => r.IsBatch))
            {
                page.Table.SelectedItems.Add(r);
            }
            var (batch, ids) = page.UndoTarget();
            Assert.Null(batch);
            Assert.Equal(2, ids.Count);
            page.Table.SelectedItems.Clear();
            page.Table.SelectedItems.Add(rows.First(r => r.IsBatch));
            Assert.Equal(rows.First(r => r.IsBatch).Id, page.UndoTarget().BatchId);
        });
    }
}
