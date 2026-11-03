using System.Windows;
using System.Windows.Controls;
using SimplySec.App.Theme;
using Wpf.Ui.Controls;
using static SimplySec.App.Theme.Ui;
using WpfButton = Wpf.Ui.Controls.Button;

namespace SimplySec.App.Dialogs;

/// <summary>A modal Fluent window: title bar, scrollable body, buttons on the right.</summary>
public class DialogWindow : FluentWindow
{
    protected StackPanel Body { get; } = VStack(10);
    protected StackPanel Footer { get; } = VStack(8);
    private readonly StackPanel _buttons = HStack(8);

    public DialogWindow(string title, double width, Window? owner = null, double maxBodyHeight = 560)
    {
        Title = title;
        Width = width;
        SizeToContent = SizeToContent.Height;
        ResizeMode = ResizeMode.NoResize;
        ShowInTaskbar = owner is null;
        ExtendsContentIntoTitleBar = true;
        WindowBackdropType = WindowBackdropType.Mica;
        WindowStartupLocation = owner is null ? WindowStartupLocation.CenterScreen : WindowStartupLocation.CenterOwner;
        if (owner is { IsLoaded: true })
        {
            Owner = owner;
        }

        var root = new DockPanel { LastChildFill = true };
        var bar = new TitleBar { Title = title, ShowMinimize = false, ShowMaximize = false };
        DockPanel.SetDock(bar, Dock.Top);
        root.Children.Add(bar);

        _buttons.HorizontalAlignment = HorizontalAlignment.Right;
        var bottom = VStack(10);
        bottom.Margin = new Thickness(20, 4, 20, 18);
        bottom.Children.Add(Footer);
        bottom.Children.Add(_buttons);
        DockPanel.SetDock(bottom, Dock.Bottom);
        root.Children.Add(bottom);

        Body.Margin = new Thickness(20, 4, 20, 8);
        root.Children.Add(new ScrollViewer
        {
            Content = Body,
            MaxHeight = maxBodyHeight,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
        });
        Content = root;
    }

    protected WpfButton AddButton(string text, Action click, bool primary = false)
    {
        var b = Button(text, click, primary);
        b.MinWidth = 96;
        _buttons.Children.Add(b);
        return b;
    }

    /// <summary>Close with a result (DialogResult only works for windows shown with ShowDialog).</summary>
    protected void Done(bool result)
    {
        try
        {
            DialogResult = result;
        }
        catch (InvalidOperationException)
        {
            Close();
        }
    }
}

/// <summary>Information, warning or a yes/no question (QMessageBox in v2).</summary>
public sealed class MessageDialog : DialogWindow
{
    public MessageDialog(string title, string text, bool question = false, Window? owner = null)
        : base(title, 460, owner)
    {
        Body.Children.Add(Text(text));
        if (question)
        {
            AddButton("Yes", () => Done(true), primary: true);
            AddButton("No", () => Done(false));
        }
        else
        {
            AddButton("OK", () => Done(true), primary: true);
        }
    }

    /// <summary>A dialog whose body is built by the caller (port and finding details).</summary>
    public MessageDialog(string title, UIElement body, double width = 560, Window? owner = null)
        : base(title, width, owner)
    {
        Body.Children.Add(body);
        AddButton("Close", () => Done(true), primary: true);
    }
}
