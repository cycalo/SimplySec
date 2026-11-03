using System.Globalization;
using SimplySec.Core.Tests.Support;

namespace SimplySec.Windows.Tests;

/// <summary>Wi-Fi profile and nmap XML parsing.</summary>
public class ParsingTests
{
    private const string Profile = """
        <?xml version="1.0"?>
        <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
          <name>{0}</name><SSIDConfig><SSID><name>{0}</name></SSID></SSIDConfig>
          <connectionType>ESS</connectionType><connectionMode>{1}</connectionMode>
          <MSM><security><authEncryption><authentication>{2}</authentication><encryption>{3}</encryption>
          <useOneX>false</useOneX></authEncryption></security></MSM>
        </WLANProfile>
        """;

    private static Wifi.Profile Parse(string name, string mode, string auth, string enc) =>
        Wifi.ParseProfile(string.Format(CultureInfo.InvariantCulture, Profile, name, mode, auth, enc))!;

    [Fact]
    public void WifiProfileParsing()
    {
        var cafe = Parse("Cafe", "auto", "open", "none");
        Assert.StartsWith("open", cafe.Weak, StringComparison.Ordinal);
        Assert.Equal("auto", cafe.ConnectionMode);
        Assert.Null(Parse("Home", "auto", "WPA3SAE", "AES").Weak);
        Assert.Contains("TKIP", Parse("Old", "manual", "WPA2PSK", "TKIP").Weak, StringComparison.Ordinal);
    }

    [Fact]
    public void WifiProfileRejectsDtd()
    {
        const string bomb = """
            <?xml version="1.0"?>
            <!DOCTYPE lolz [<!ENTITY lol "lol">]>
            <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"><name>&lol;</name></WLANProfile>
            """;
        Assert.ThrowsAny<System.Xml.XmlException>(() => Wifi.ParseProfile(bomb));
    }

    [Fact]
    public void NmapXml()
    {
        var xml = File.ReadAllText(Path.Combine(Golden.RepoRoot, "tests", "fixtures", "igd", "nmap.xml"));
        var hosts = Nmap.ParseXml(xml);
        var h = Assert.Single(hosts);
        Assert.Equal(("192.168.1.20", "AC:DE:48:00:11:22", "camera.home"), (h.Ip, h.Mac, h.Hostname));
        Assert.Equal([23, 554], h.Services.Select(s => s.Port).Order());
    }
}
