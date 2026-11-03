using System.Windows;
using System.Windows.Controls;
using SimplySec.App.Controls;
using SimplySec.App.Theme;
using SimplySec.App.ViewModels;
using SimplySec.Core.Model;
using static SimplySec.App.Theme.Ui;

namespace SimplySec.App.Views;

/// <summary>A scrollable page with a title; subclasses fill <see cref="Body"/> (v2's pages.Page).</summary>
public abstract class PageView : UserControl
{
    protected MainViewModel Vm { get; }
    protected StackPanel Header { get; } = VStack(12);
    protected StackPanel Body { get; } = VStack(12);
    public ScrollViewer Scroller { get; }

    protected PageView(MainViewModel vm, string title, string subtitle = "")
    {
        Vm = vm;
        Header.Children.Add(Text(title, TextStyle.PageTitle));
        if (subtitle.Length > 0)
        {
            Header.Children.Add(Text(subtitle, TextStyle.Dim));
        }
        var inner = VStack(12);
        inner.Margin = new Thickness(28, 4, 28, 24);
        inner.Children.Add(Header);
        inner.Children.Add(Body);
        Scroller = new ScrollViewer { Content = inner, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        Content = Scroller;
        // The page scrolls itself: tell NavigationView not to wrap it in another scroll viewer.
        ScrollViewer.SetCanContentScroll(this, true);
        PreviewMouseWheel += OnWheel;
    }

    /// <summary>
    /// Mouse wheel anywhere on the page scrolls it. A table under the mouse scrolls first while it
    /// can; at its ends the page takes over. Whichever scroll viewer can actually move is used,
    /// so it works whether or not NavigationView wraps the page in its own.
    /// </summary>
    private void OnWheel(object sender, System.Windows.Input.MouseWheelEventArgs e)
    {
        for (var d = e.OriginalSource as DependencyObject; d is not null && d != this; d = UpOf(d))
        {
            if (d is ScrollViewer inner && inner != Scroller && CanScroll(inner, e.Delta))
            {
                return; // e.g. a DataGrid with rows left to scroll
            }
        }
        var target = CanScroll(Scroller, e.Delta) ? Scroller : null;
        for (var d = UpOf(this); target is null && d is not null; d = UpOf(d))
        {
            if (d is ScrollViewer outer && CanScroll(outer, e.Delta))
            {
                target = outer;
            }
        }
        if (target is not null)
        {
            target.ScrollToVerticalOffset(target.VerticalOffset - e.Delta);
            e.Handled = true;
        }
    }

    private static bool CanScroll(ScrollViewer s, int delta) =>
        delta > 0 ? s.VerticalOffset > 0 : s.VerticalOffset < s.ScrollableHeight;

    private static DependencyObject? UpOf(DependencyObject d) =>
        d is System.Windows.Media.Visual or System.Windows.Media.Media3D.Visual3D
            ? System.Windows.Media.VisualTreeHelper.GetParent(d)
            : LogicalTreeHelper.GetParent(d);

    protected FindingCard FindingCardFor(Finding f, bool compact = false, bool showArea = false, bool showAdvice = false)
    {
        var c = new FindingCard(f, compact, showArea, showAdvice);
        c.FixRequested += Vm.RequestFix;
        c.KeepRequested += Vm.Keep;
        c.UnkeepRequested += fi =>
        {
            if (fi.KeepKey is not null)
            {
                Vm.Unkeep(fi.KeepKey);
            }
        };
        return c;
    }
}
