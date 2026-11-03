using System.Globalization;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using SimplySec.App.Theme;
using SimplySec.App.ViewModels;
using SimplySec.Core.Compat;
using SimplySec.Core.Engine;
using SimplySec.Core.Lan;
using static SimplySec.App.Theme.Ui;

namespace SimplySec.App.Views;

/// <summary>Administrator status, daily check, owned networks, accepted risks, data folders (port of pages/settings.py).</summary>
public sealed class SettingsPage : PageView
{
    private readonly TextBlock _adminText = Text();
    private readonly Wpf.Ui.Controls.Button _restart;
    private readonly CheckBox _daily = new() { Content = "Run the daily check at", VerticalAlignment = VerticalAlignment.Center };
    private readonly ComboBox _hour = new() { Width = 72 };
    private readonly ComboBox _minute = new() { Width = 72 };
    private readonly TextBlock _dailyStatus = Text("", TextStyle.Dim);
    private readonly StackPanel _nets = VStack(8);
    private readonly StackPanel _accepted = VStack(8);

    public event Action? RestartRequested;

    public SettingsPage(MainViewModel vm) : base(vm, "Settings")
    {
        var admin = VStack(8);
        admin.Children.Add(Text("Administrator", TextStyle.SectionTitle));
        admin.Children.Add(_adminText);
        _restart = Button("Restart as administrator", () => RestartRequested?.Invoke());
        _restart.HorizontalAlignment = HorizontalAlignment.Left;
        admin.Children.Add(_restart);
        Body.Children.Add(Card(admin));

        Body.Children.Add(Card(DailyCheckSection()));
        Body.Children.Add(Card(_nets));
        Body.Children.Add(Card(_accepted));

        var data = VStack(10);
        data.Children.Add(Text("Data folders", TextStyle.SectionTitle));
        foreach (var (title, path) in new[]
        {
            ("Change journal and firewall backups (only administrators can change these)", vm.Services.DataDir),
            ("Your scan history, settings and log", vm.Services.UserDir),
        })
        {
            var r = new DockPanel();
            var open = Button("Open", () =>
            {
                if (Directory.Exists(path))
                {
                    vm.Services.OpenPath(path);
                }
            });
            DockPanel.SetDock(open, Dock.Right);
            r.Children.Add(open);
            var text = Rich(R($"{title}:"), Br(), new System.Windows.Documents.Run(path) { FontFamily = new System.Windows.Media.FontFamily("Cascadia Mono, Consolas") });
            r.Children.Add(text);
            data.Children.Add(r);
        }
        Body.Children.Add(Card(data));

        vm.ScanFinished += _ => Refresh();
        Refresh();
    }

    private StackPanel DailyCheckSection()
    {
        var dl = VStack(8);
        dl.Children.Add(Text("Daily check", TextStyle.SectionTitle));
        dl.Children.Add(Text("Once a day SimplySec runs a read-only scan in the background and shows a notification only if something got worse: the risk score rises by 5 or more, a new high-risk finding, a new device on your network, or antivirus or the firewall turned off. It never changes anything. The scheduled task is recorded on the Changes page.", TextStyle.Dim));
        for (var h = 0; h < 24; h++)
        {
            _hour.Items.Add(h.ToString("00", CultureInfo.InvariantCulture));
        }
        for (var m = 0; m < 60; m++)
        {
            _minute.Items.Add(m.ToString("00", CultureInfo.InvariantCulture));
        }
        var settings = DailySettings();
        var parts = (Js.Str(settings["time"]) is { Length: > 0 } t ? t : "12:00").Split(':');
        _hour.SelectedItem = parts[0].PadLeft(2, '0');
        _minute.SelectedItem = parts.Length > 1 ? parts[1].PadLeft(2, '0') : "00";
        _daily.IsChecked = Js.Truthy(settings["enabled"]);
        var row = HStack(8);
        row.Children.Add(_daily);
        row.Children.Add(_hour);
        row.Children.Add(new TextBlock { Text = ":", VerticalAlignment = VerticalAlignment.Center });
        row.Children.Add(_minute);
        row.Children.Add(Button("Apply", () => Vm.SetDailyCheck(_daily.IsChecked == true, DailyTime)));
        dl.Children.Add(row);
        dl.Children.Add(_dailyStatus);
        return dl;
    }

    public string DailyTime => $"{_hour.SelectedItem ?? "12"}:{_minute.SelectedItem ?? "00"}";

    private JsonObject DailySettings()
    {
        try
        {
            return Vm.Engine.History.GetSetting(DailyCheck.Setting, new JsonObject()) as JsonObject ?? [];
        }
        catch (Exception)
        {
            return [];
        }
    }

    public void Refresh()
    {
        var admin = Vm.IsAdmin;
        _adminText.Text = admin
            ? "SimplySec is running as administrator: fixes and undo apply directly."
            : "SimplySec is running in read-only mode. Scans work fully; fixes and undo ask Windows for administrator permission each time, or you can restart as administrator.";
        _restart.Visibility = admin ? Visibility.Collapsed : Visibility.Visible;

        FillNetworks();
        var settings = DailySettings();
        _dailyStatus.Text = Js.Truthy(settings["enabled"]) ? $"On, daily at {Js.Str(settings["time"])}." : "Off.";

        _accepted.Children.Clear();
        _accepted.Children.Add(Text("Accepted risks (Keep)", TextStyle.SectionTitle));
        List<JsonObject> accepted;
        try
        {
            accepted = Vm.Engine.History.Accepted();
        }
        catch (Exception exc)
        {
            _accepted.Children.Add(Text($"Could not read: {exc.Message}", TextStyle.Dim));
            return;
        }
        if (accepted.Count == 0)
        {
            _accepted.Children.Add(Text("None. Use 'Keep: I need this' on a finding to stop scoring it.", TextStyle.Dim));
        }
        foreach (var a in accepted)
        {
            var key = Js.Str(a["keep_key"]);
            var title = Js.Str(a["title"]) is { Length: > 0 } t ? t : key;
            var created = Js.Str(a["created"]);
            var r = new DockPanel();
            var again = Button("Score again", () => Vm.Unkeep(key));
            DockPanel.SetDock(again, Dock.Right);
            r.Children.Add(again);
            r.Children.Add(Rich(R(title), Br(), new System.Windows.Documents.Run($"since {created[..Math.Min(10, created.Length)]}") { FontSize = 12 }));
            _accepted.Children.Add(r);
        }
    }

    private void FillNetworks()
    {
        _nets.Children.Clear();
        _nets.Children.Add(Text("Networks I own", TextStyle.SectionTitle));
        JsonObject nets;
        try
        {
            nets = LanScan.OwnedNetworks(Vm.Engine.History);
        }
        catch (Exception exc)
        {
            _nets.Children.Add(Text($"Could not read: {exc.Message}", TextStyle.Dim));
            return;
        }
        if (nets.Count == 0)
        {
            _nets.Children.Add(Text("None yet. SimplySec asks before it scans a network for devices.", TextStyle.Dim));
        }
        foreach (var (key, info) in nets)
        {
            var confirmed = Js.Str(Js.Get(info, "confirmed"));
            var label = Js.Str(Js.Get(info, "label")) is { Length: > 0 } l ? l : key;
            var r = new DockPanel();
            var forget = Button("Forget", () =>
            {
                LanScan.ForgetNetwork(Vm.Engine.History, key);
                Refresh();
            });
            DockPanel.SetDock(forget, Dock.Right);
            r.Children.Add(forget);
            r.Children.Add(Rich(R(label), Br(), new System.Windows.Documents.Run($"confirmed {confirmed[..Math.Min(10, confirmed.Length)]}") { FontSize = 12 }));
            _nets.Children.Add(r);
        }
    }
}
