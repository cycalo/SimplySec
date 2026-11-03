using System.Text.Json.Nodes;
using SimplySec.Windows.Interop;

namespace SimplySec.Windows.Tests;

/// <summary>Native interop on this PC (read-only): struct layouts and psutil-equivalent behaviour.</summary>
public class NativeTests
{
    [Theory]
    [InlineData(@"\??\C:\Windows\x.exe", @"C:\Windows\x.exe")]
    [InlineData(@"\Device\Mup\server\share\tools\x.exe", @"\\server\share\tools\x.exe")]
    [InlineData(@"\??\UNC\server\share\x.exe", @"\\server\share\x.exe")]
    [InlineData(@"\\server\share\x.exe", @"\\server\share\x.exe")]
    [InlineData(@"\Device\NoSuchVolume99\x.exe", @"\x.exe")]
    public void ConvertDosPathLikePsutil(string nt, string expected) => Assert.Equal(expected, Listeners.ConvertDosPath(nt));

    [Fact]
    public void ImagePathOfThisProcess()
    {
        var expected = Environment.ProcessPath!;
        Assert.Equal(expected, Listeners.ProcessExe(Environment.ProcessId), StringComparer.OrdinalIgnoreCase);
        // The fallback used for processes that cannot be opened (SYSTEM services when not elevated).
        var nt = Listeners.NtImageName(Environment.ProcessId);
        Assert.StartsWith(@"\Device\", nt, StringComparison.Ordinal);
        Assert.Equal(expected, Listeners.ConvertDosPath(nt), StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void ImagePathOfProtectedProcess()
    {
        // lsass.exe cannot be opened without elevation (and not even then, when protected).
        var lsass = System.Diagnostics.Process.GetProcessesByName("lsass").Single();
        var sys32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "lsass.exe");
        Assert.Equal(sys32, Listeners.ProcessExe(lsass.Id), StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void LoopbackAdapterLikePsutil()
    {
        var lo = Network.LocalInterfaces().Single(i => i.Alias == "Loopback Pseudo-Interface 1");
        Assert.Equal(["127.0.0.1/8", "::1/128"], lo.Addresses);
        Assert.Equal("", lo.Mac);
        Assert.True(lo.Up);
    }

    [Fact]
    public void AdapterAddressesIpv4First()
    {
        foreach (var (alias, addresses, _, _) in Network.LocalInterfaces())
        {
            var firstV6 = addresses.FindIndex(a => a.Contains(':', StringComparison.Ordinal));
            if (firstV6 >= 0)
            {
                Assert.True(addresses.Skip(firstV6).All(a => a.Contains(':', StringComparison.Ordinal)), $"{alias}: {string.Join(", ", addresses)}");
            }
        }
    }

    [Fact]
    public void WindowsPowerShellLoadsItsOwnModules()
    {
        // Fails when PowerShell 7's PSModulePath leaks into powershell.exe (e.g. run from pwsh).
        var status = Runner.PowerShellJson("ConvertTo-Json ([string](Get-AuthenticodeSignature -LiteralPath \"$env:SystemRoot\\explorer.exe\").Status)");
        Assert.Equal("Valid", status!.GetValue<string>());
    }

    [Fact]
    public void SignatureOfMissingFileIsUnreadable() =>
        Assert.Equal("Unreadable", WinTrust.Verify(@"C:\definitely\missing\nothing.exe").Status);

    [Fact]
    public void ParametersTravelAsJson()
    {
        var echoed = Runner.PowerShellJson("ConvertTo-Json -Compress $P.text", new JsonObject { ["text"] = "a'b\"c$(x)" });
        Assert.Equal("a'b\"c$(x)", echoed!.GetValue<string>());
    }
}
