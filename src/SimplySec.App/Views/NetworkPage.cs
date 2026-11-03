using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using SimplySec.App.Controls;
using SimplySec.App.Theme;
using SimplySec.App.ViewModels;
using SimplySec.Core.Compat;
using SimplySec.Core.Knowledge;
using SimplySec.Core.Lan;
using SimplySec.Core.Model;
using static SimplySec.App.Theme.Ui;

namespace SimplySec.App.Views;

/// <summary>A row of the devices table.</summary>
public sealed class DeviceRow(MainViewModel vm, string mac, bool trusted) : INotifyPropertyChanged
{
    private bool _trusted = trusted;
    public string Mac { get; } = mac;
    public string Name { get; init; } = "";
    public string Vendor { get; init; } = "";
    public string Ip { get; init; } = "";
    public string FirstSeen { get; init; } = "";
    public string LastSeen { get; init; } = "";
    public string Services { get; init; } = "";
    public string? ServicesTip { get; init; }

    public bool Trusted
    {
        get => _trusted;
        set
        {
            if (_trusted == value)
            {
                return;
            }
            _trusted = value;
            if (Mac.Length > 0)
            {
                vm.Engine.History.SetDeviceTrusted(Mac, value);
            }
            Changed();
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void Changed([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>Devices, the router (UPnP port forwards) and this PC's saved Wi-Fi networks (port of pages/network.py).</summary>
public sealed class NetworkPage : PageView
{
    private readonly Wpf.Ui.Controls.Button _scan;
    private readonly CheckBox _deep = new() { Content = "Deep scan with nmap (if installed)", VerticalAlignment = VerticalAlignment.Center };
    private readonly TextBlock _targets = Text("", TextStyle.Dim);
    public DataGrid Table { get; } = new()
    {
        AutoGenerateColumns = false,
        HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
        CanUserAddRows = false,
        SelectionMode = DataGridSelectionMode.Single,
        HeadersVisibility = DataGridHeadersVisibility.Column,
        Height = 260,
    };
    private readonly StackPanel _advice = VStack(10);
    private readonly Dictionary<string, FindingCard> _deviceCards = new(StringComparer.Ordinal);
    private readonly StackPanel _router = VStack(6);
    private readonly StackPanel _wifi = VStack(6);

    public NetworkPage(MainViewModel vm)
        : base(vm, "My network",
            "Devices on your home network, your router's port forwards and this PC's saved Wi-Fi networks. SimplySec only scans networks you confirm are yours, and never changes other devices.")
    {
        var row = HStack(12);
        _scan = Button("Scan my network", Scan, primary: true);
        row.Children.Add(_scan);
        row.Children.Add(_deep);
        Body.Children.Add(row);
        Body.Children.Add(_targets);

        Body.Children.Add(Text("Devices", TextStyle.SectionTitle));
        // A real CheckBox in each row: one click toggles it (a DataGridCheckBoxColumn first selects
        // the row, then needs a second click).
        var check = new FrameworkElementFactory(typeof(CheckBox));
        check.SetBinding(System.Windows.Controls.Primitives.ToggleButton.IsCheckedProperty,
            new Binding(nameof(DeviceRow.Trusted)) { Mode = BindingMode.TwoWay, UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged });
        check.SetValue(HorizontalAlignmentProperty, HorizontalAlignment.Center);
        check.SetValue(FrameworkElement.ToolTipProperty, "Trusted devices aren't reported as new or unknown.");
        Table.Columns.Add(new DataGridTemplateColumn
        {
            Header = "Trusted",
            CellTemplate = new DataTemplate { VisualTree = check },
            Width = 70,
        });
        foreach (var (header, path, width) in new[]
        {
            ("Name", nameof(DeviceRow.Name), 190.0), ("Vendor", nameof(DeviceRow.Vendor), 150), ("IP", nameof(DeviceRow.Ip), 110),
            ("First seen", nameof(DeviceRow.FirstSeen), 95), ("Last seen", nameof(DeviceRow.LastSeen), 95), ("Services", nameof(DeviceRow.Services), double.NaN),
        })
        {
            var style = new Style(typeof(TextBlock));
            style.Setters.Add(new Setter(TextBlock.MarginProperty, new Thickness(4, 2, 4, 2)));
            if (path == nameof(DeviceRow.Services))
            {
                style.Setters.Add(new Setter(FrameworkElement.ToolTipProperty, new Binding(nameof(DeviceRow.ServicesTip))));
            }
            Table.Columns.Add(new DataGridTextColumn
            {
                Header = header,
                Binding = new Binding(path) { Mode = BindingMode.OneWay },
                IsReadOnly = true,
                Width = double.IsNaN(width) ? new DataGridLength(1, DataGridLengthUnitType.Star) : new DataGridLength(width),
                ElementStyle = style,
            });
        }
        // Jumping to a device's advice is on right-click or double-click, not on every selection.
        Table.ContextMenu = new ContextMenu();
        Table.ContextMenuOpening += OnRowMenu;
        Table.MouseDoubleClick += (_, e) =>
        {
            if (RowAt(e.OriginalSource) is { } d)
            {
                JumpTo(d.Mac);
            }
        };
        Body.Children.Add(Table);

        Body.Children.Add(Text("What to do about your devices", TextStyle.SectionTitle));
        Body.Children.Add(Text("SimplySec never changes other devices. Each card says what the risk is and what to change in that device's settings or app. Right-click or double-click a device in the table to jump to its card.", TextStyle.Dim));
        Body.Children.Add(_advice);
        Body.Children.Add(Card(_router));
        Body.Children.Add(Card(_wifi));

        vm.ScanFinished += _ => Refresh();
        vm.BusyChanged += (busy, _) => _scan.IsEnabled = !busy;
        Refresh();
    }

    // ------------------------------------------------------------------ actions

    private void Scan()
    {
        var result = Vm.Result;
        if (result is null)
        {
            Vm.Dialogs.Info("Scan first", "Run a scan of this PC first (Overview > Scan & Protect).");
            return;
        }
        var targets = Discovery.ScanTargets(result.Interfaces);
        if (targets.Count == 0)
        {
            Vm.Dialogs.Info("No home network",
                "This PC isn't connected to a home network SimplySec can scan (only VPN, virtual or public-address adapters).");
            return;
        }
        var history = Vm.Engine.History;
        foreach (var t in targets)
        {
            if (LanScan.IsOwned(history, t))
            {
                continue;
            }
            if (Vm.Dialogs.Ask("Is this your network?",
                    $"Is {t.Label} your network?\n\nSimplySec will look for devices on it and check which services they offer. Only scan networks you own or manage, never public Wi-Fi."))
            {
                LanScan.SetOwned(history, t, true);
            }
        }
        var owned = targets.Where(t => LanScan.IsOwned(history, t)).ToList();
        if (owned.Count > 0)
        {
            Vm.ScanNetwork(owned, _deep.IsChecked == true);
        }
        Refresh();
    }

    // ------------------------------------------------------------------ display

    public void Refresh()
    {
        var result = Vm.Result;
        var history = Vm.Engine.History;
        if (result is not null)
        {
            var parts = Discovery.ScanTargets(result.Interfaces)
                .Select(t => $"{t.Label}: {(LanScan.IsOwned(history, t) ? "confirmed as yours" : "not confirmed yet (you'll be asked)")}")
                .ToList();
            _targets.Text = parts.Count > 0 ? string.Join("\n", parts) : "No home network found on this PC's adapters.";
        }
        var extras = result?.Extras ?? [];
        FillDevices(extras["devices"] is JsonArray devices ? devices.OfType<JsonObject>().ToList() : StoredDevices());
        var findings = (result?.Findings ?? []).Where(f => f.Status == FindingStatus.Open).ToList();
        FillAdvice(findings.Where(f => f.Check == "lan").ToList());
        FillRouter(extras["router"] as JsonObject ?? []);
        foreach (var f in findings.Where(f => f.Check == "router" && f.Severity > Severity.Info))
        {
            _router.Children.Add(FindingCardFor(f, showAdvice: true));
        }
        FillWifi(result is not null ? Js.Get(result.Facts["wifi"], "value") : null);
    }

    private void FillAdvice(List<Finding> findings)
    {
        _advice.Children.Clear();
        _deviceCards.Clear();
        if (findings.Count == 0)
        {
            var scanned = Vm.Result?.Extras["devices"] is JsonArray { Count: > 0 };
            _advice.Children.Add(Text(scanned ? "No risky services or unknown new devices found." : "Scan your network to get advice about its devices.", TextStyle.Dim));
            return;
        }
        foreach (var f in findings)
        {
            var c = FindingCardFor(f, showAdvice: true);
            var mac = f.Id[(f.Id.LastIndexOf('.') + 1)..];
            _deviceCards.TryAdd(mac, c);
            _advice.Children.Add(c);
        }
    }

    private static DeviceRow? RowAt(object source)
    {
        for (var d = source as DependencyObject; d is not null; d = d is Visual ? VisualTreeHelper.GetParent(d) : LogicalTreeHelper.GetParent(d))
        {
            if (d is DataGridRow row)
            {
                return row.Item as DeviceRow;
            }
        }
        return null;
    }

    /// <summary>Right-click on a device: jump to its advice, or change Trusted.</summary>
    private void OnRowMenu(object sender, ContextMenuEventArgs e)
    {
        if (RowAt(e.OriginalSource) is not { } device)
        {
            e.Handled = true; // header or empty space: no menu
            return;
        }
        Table.SelectedItem = device;
        var menu = Table.ContextMenu!;
        menu.Items.Clear();
        var hasCard = _deviceCards.ContainsKey(device.Mac);
        var show = new MenuItem { Header = hasCard ? "Show what to do about this device" : "No advice for this device", IsEnabled = hasCard };
        show.Click += (_, _) => JumpTo(device.Mac);
        menu.Items.Add(show);
        var trusted = new MenuItem { Header = "Trusted", IsCheckable = true, IsChecked = device.Trusted, IsEnabled = device.Mac.Length > 0 };
        trusted.Click += (_, _) => device.Trusted = trusted.IsChecked;
        menu.Items.Add(trusted);
    }

    /// <summary>MACs of the devices that have an advice card.</summary>
    public IReadOnlyCollection<string> DevicesWithAdvice => _deviceCards.Keys;

    private void JumpTo(string mac)
    {
        if (!_deviceCards.TryGetValue(mac, out var card))
        {
            return;
        }
        card.BringIntoView(new Rect(0, -40, card.ActualWidth, card.ActualHeight + 40));
        var frame = card.Frame;
        var old = (frame.BorderBrush, frame.BorderThickness);
        frame.SetResourceReference(Border.BorderBrushProperty, Ui.Accent);
        frame.BorderThickness = new Thickness(2);
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        timer.Tick += (_, _) =>
        {
            timer.Stop();
            frame.SetResourceReference(Border.BorderBrushProperty, Ui.CardStroke);
            frame.BorderThickness = old.BorderThickness;
        };
        timer.Start();
    }

    private List<JsonObject> StoredDevices() =>
        Vm.Engine.History.Devices().Select(d => new JsonObject
        {
            ["ip"] = d["ip"]?.DeepClone(),
            ["mac"] = d["mac"]?.DeepClone(),
            ["vendor"] = d["vendor"]?.DeepClone(),
            ["name"] = Js.Truthy(d["label"]) ? Js.Str(d["label"]) : Js.Truthy(d["name"]) ? Js.Str(d["name"]) : "",
            ["first_seen"] = d["first_seen"]?.DeepClone(),
            ["last_seen"] = d["last_seen"]?.DeepClone(),
            ["trusted"] = d["trusted"]?.DeepClone(),
            ["open_ports"] = Js.Get(d["data"], "open_ports")?.DeepClone() ?? new JsonArray(),
            ["randomized"] = false,
        }).ToList();

    private static string S(JsonObject d, string key) => d[key] is JsonValue v && v.TryGetValue<string>(out var s) ? s : "";

    private static string First10(string s) => s.Length > 10 ? s[..10] : s;

    private void FillDevices(List<JsonObject> devices)
    {
        var kb = KnowledgeBase.Get();
        var rows = new List<DeviceRow>();
        foreach (var d in devices)
        {
            var name = S(d, "name");
            if (name.Length == 0 && Js.Truthy(d["randomized"]))
            {
                name = "Private address (likely a phone)";
            }
            else if (name.Length == 0)
            {
                name = S(d, "vendor").Length > 0 ? $"{S(d, "vendor")} device" : "Unknown device";
            }
            if (Js.Truthy(d["is_gateway"]))
            {
                name = $"{(name.Length > 0 ? name : "Router")} (router)";
            }
            if (Js.Truthy(d["new"]))
            {
                name = $"{name} – new";
            }
            var ports = Js.AsList(d["open_ports"]).Select(p => (int)Js.Long(p)).ToList();
            var dev = new Device { Ip = S(d, "ip"), Mac = S(d, "mac"), OpenPorts = ports, IsGateway = Js.Truthy(d["is_gateway"]) };
            var risky = Inventory.RiskyServices(dev, kb).Select(x => x.Port).ToHashSet();
            var services = ports.Select(p =>
            {
                var info = kb.Port("tcp", p);
                var text = info is not null ? $"{p} {info.Name}" : p.ToString(System.Globalization.CultureInfo.InvariantCulture);
                return risky.Contains(p) ? $"⚠ {text}" : text;
            });
            rows.Add(new DeviceRow(Vm, S(d, "mac"), Js.Truthy(d["trusted"]))
            {
                Name = name,
                Vendor = S(d, "vendor"),
                Ip = S(d, "ip"),
                FirstSeen = First10(S(d, "first_seen")),
                LastSeen = First10(S(d, "last_seen")),
                Services = string.Join(", ", services),
                ServicesTip = risky.Count > 0 ? "⚠ marks services that are often attacked" : null,
            });
        }
        Table.ItemsSource = rows;
    }

    private void FillRouter(JsonObject router)
    {
        _router.Children.Clear();
        _router.Children.Add(Text("Router", TextStyle.SectionTitle));
        if (router.Count == 0)
        {
            _router.Children.Add(Text("Scan your network to read your router's UPnP status and port forwards.", TextStyle.Dim));
            return;
        }
        if (!Js.Truthy(router["found"]))
        {
            _router.Children.Add(Text("Your router does not offer UPnP port forwarding. That's the safer setting."));
            return;
        }
        var name = S(router, "friendly_name") is { Length: > 0 } fn ? fn : S(router, "model") is { Length: > 0 } m ? m : "Your router";
        var ext = S(router, "external_ip") is { Length: > 0 } e ? e : "unknown";
        var cgnat = Js.Truthy(router["external_is_private"]) ? " (a private address: your provider blocks connections from the internet)" : "";
        _router.Children.Add(Rich(B(name), R($" has UPnP turned on. Internet address: {ext}{cgnat}.")));
        var maps = Js.AsList(router["mappings"]).OfType<JsonObject>().ToList();
        if (maps.Count == 0)
        {
            _router.Children.Add(Text("No port forwards are open right now.", TextStyle.Dim));
        }
        foreach (var mp in maps)
        {
            var desc = S(mp, "description") is { Length: > 0 } dsc ? dsc : "no description";
            _router.Children.Add(Text($"{Js.Str(mp["protocol"])} {Js.Str(mp["external_port"])} → {Js.Str(mp["internal_client"])}:{Js.Str(mp["internal_port"])} – {desc}"));
        }
        if (S(router, "error") is { Length: > 0 } err)
        {
            _router.Children.Add(Text($"Note: {err}", TextStyle.Dim));
        }
    }

    private void FillWifi(JsonNode? profiles)
    {
        _wifi.Children.Clear();
        _wifi.Children.Add(Text("Saved Wi-Fi networks on this PC", TextStyle.SectionTitle));
        var items = Js.AsList(profiles).OfType<JsonObject>().ToList();
        if (items.Count == 0)
        {
            _wifi.Children.Add(Text("No saved Wi-Fi networks (or no Wi-Fi adapter).", TextStyle.Dim));
            return;
        }
        foreach (var p in items)
        {
            var weak = S(p, "weak");
            var sec = weak.Length > 0 ? weak : $"{Js.Str(p["authentication"])} / {Js.Str(p["encryption"])}";
            var mode = S(p, "connection_mode") == "auto" ? "connects automatically" : "only when you choose it";
            _wifi.Children.Add(Rich(R(weak.Length > 0 ? "⚠ " : ""), B(S(p, "name")), R($" – {sec}, {mode}")));
        }
    }
}
