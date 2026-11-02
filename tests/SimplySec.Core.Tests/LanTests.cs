using System.Text;
using System.Text.Json.Nodes;
using System.Xml;
using SimplySec.Core.Compat;
using SimplySec.Core.Engine;
using SimplySec.Core.Knowledge;
using SimplySec.Core.Lan;
using SimplySec.Core.Model;
using SimplySec.Core.Report;
using SimplySec.Core.Storage;
using SimplySec.Core.Tests.Support;

namespace SimplySec.Core.Tests;

/// <summary>Home network, router and report (port of test_lan.py and test_report.py; no network access).</summary>
public class LanTests
{
    static LanTests() => Pinned.Apply();

    private static byte[] Read(string name) => File.ReadAllBytes(Path.Combine(Golden.RepoRoot, "tests", "fixtures", "igd", name));

    private static IpNet Net(string s) => PyIp.TryParseNetwork(s, out var n) ? n : throw new ArgumentException(s);

    [Fact]
    public void OuiLookupAndRandomizedMacs()
    {
        var db = OuiDatabase.Default;
        Assert.True(db.Entries.Count > 30000);
        Assert.Contains("Intel", db.Vendor("64-BC-58-C0-B0-70"), StringComparison.Ordinal);
        Assert.Contains("VMware", db.Vendor("00:50:56:C0:00:01"), StringComparison.Ordinal);
        Assert.True(Identify.IsRandomized("DA:A1:19:00:00:01"));
        Assert.False(Identify.IsRandomized("64:BC:58:C0:B0:70"));
        Assert.Equal("", db.Vendor("DA:A1:19:00:00:01"));
        Assert.StartsWith("Device with a private address", Identify.Describe("DA:A1:19:00:00:01", "", ""), StringComparison.Ordinal);
        Assert.Equal("FC:34:97:A8:56:70", Identify.NormalizeMac("fc-34-97-a8-56-70"));
        Assert.True(Identify.IsMulticast("01:00:5E:7F:FF:FA"));
    }

    private static NetInterface Iface(string alias, InterfaceKind kind, string addr, bool up = true, string name = "") => new()
    {
        Index = 1, Alias = alias, Kind = kind, Addresses = [addr], Up = up, Profile = Profile.Public, NetworkName = name, Gateways = ["192.168.1.1"],
    };

    [Fact]
    public void ScanTargetsScope()
    {
        var targets = Discovery.ScanTargets(
        [
            Iface("Ethernet", InterfaceKind.Ethernet, "192.168.1.71/24", name: "EE-G9QKJQ"),
            Iface("Tailscale", InterfaceKind.Vpn, "100.87.181.68/32"),
            Iface("VMnet1", InterfaceKind.Virtual, "192.168.38.1/24"),
            Iface("Big", InterfaceKind.Wifi, "10.20.30.40/16"),
            Iface("Down", InterfaceKind.Ethernet, "192.168.5.2/24", up: false),
            Iface("Public IP", InterfaceKind.Ethernet, "81.2.69.142/24"),
        ]);
        Assert.Equal(new Dictionary<string, string> { ["Ethernet"] = "192.168.1.0/24", ["Big"] = "10.20.28.0/22" },
            targets.ToDictionary(t => t.Interface, t => t.Network.ToString()));
        var eth = targets.First(t => t.Interface == "Ethernet");
        Assert.Equal("EE-G9QKJQ|192.168.1.0/24", eth.Key);
        var hosts = Discovery.HostsOf(eth);
        Assert.DoesNotContain("192.168.1.71", hosts);
        Assert.Equal(253, hosts.Count);
    }

    [Fact]
    public void SsdpParsingAndUrlSafety()
    {
        var raw = Encoding.UTF8.GetBytes("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLOCATION: http://192.168.1.254:49152/rootDesc.xml\r\nSERVER: Linux UPnP/1.0\r\n\r\n");
        var r = Ssdp.ParseResponse(raw, "192.168.1.254");
        Assert.True(r is not null && r.Location.EndsWith("rootDesc.xml", StringComparison.Ordinal) && r.St.Contains("InternetGateway", StringComparison.Ordinal));
        List<IpNet> lan = [Net("192.168.1.0/24")];
        Ssdp.CheckLanUrl("http://192.168.1.254:49152/x.xml", lan);
        foreach (var bad in new[] { "https://192.168.1.254/x", "http://example.com/x", "http://8.8.8.8/x", "http://10.0.0.1/x", "file:///c:/x" })
        {
            Assert.Throws<UnsafeUrlException>(() => Ssdp.CheckLanUrl(bad, lan));
        }
    }

    [Fact]
    public void EntityBombIsRejected()
    {
        Assert.Throws<XmlException>(() => Ssdp.ParseXml(Read("entity_bomb.xml")));
        Assert.Throws<XmlException>(() => Ssdp.DeviceName(Read("entity_bomb.xml")));
    }

    [Fact]
    public void IgdDescriptionAndSoap()
    {
        var (stype, control) = UpnpIgd.FindWanService(Read("description.xml"), "http://192.168.1.254:49152/rootDesc.xml");
        Assert.Equal("urn:schemas-upnp-org:service:WANIPConnection:1", stype);
        Assert.Equal("http://192.168.1.254:49152/upnp/control/WANIPConn1", control);
        Assert.Equal(("Smart Hub 2", "EE", "SH2"), Ssdp.DeviceName(Read("description.xml")));
        Assert.Equal(new Dictionary<string, string> { ["NewExternalIPAddress"] = "81.2.69.142" }, UpnpIgd.ParseSoap(Read("external_ip.xml")));
        var m = UpnpIgd.MappingFrom(UpnpIgd.ParseSoap(Read("mapping_0.xml")));
        Assert.Equal((25565, "TCP", "192.168.1.71", "Minecraft server"), (m.ExternalPort, m.Protocol, m.InternalClient, m.Description));
        var fault = Assert.Throws<SoapFault>(() => UpnpIgd.ParseSoap(Read("fault_713.xml")));
        Assert.Equal("713", fault.Code);
        var env = Encoding.UTF8.GetString(UpnpIgd.SoapEnvelope(stype, "GetGenericPortMappingEntry", [("NewPortMappingIndex", "0")]));
        Assert.Contains("<NewPortMappingIndex>0</NewPortMappingIndex>", env, StringComparison.Ordinal);
    }

    private sealed class FakeSsdp : ISsdp
    {
        public List<string> Calls { get; } = [];

        public List<SsdpResponse> Search(string st = "ssdp:all", double timeout = 3, string bindIp = "") =>
            [new SsdpResponse("192.168.1.254", "http://192.168.1.254:49152/rootDesc.xml", st)];

        public (int Status, byte[] Body) Fetch(string url, List<IpNet>? allowed, double timeout = 4, byte[]? data = null, Dictionary<string, string>? headers = null)
        {
            Ssdp.CheckLanUrl(url, allowed);
            if (data is null)
            {
                return (200, Read("description.xml"));
            }
            var action = headers!["SOAPAction"].Split('#')[1].Trim('"');
            Calls.Add(action);
            if (action == "GetExternalIPAddress")
            {
                return (200, Read("external_ip.xml"));
            }
            var text = Encoding.UTF8.GetString(data);
            var index = int.Parse(text.Split("<NewPortMappingIndex>")[1].Split('<')[0], System.Globalization.CultureInfo.InvariantCulture);
            return index < 2 ? (200, Read($"mapping_{index}.xml")) : (500, Read("fault_713.xml"));
        }
    }

    [Fact]
    public void ReadRouterLoopsUntilFault713()
    {
        var fake = new FakeSsdp();
        var info = UpnpIgd.ReadRouter(fake, ["192.168.1.254"], [Net("192.168.1.0/24")]);
        Assert.True(info.Found && info.ExternalIp == "81.2.69.142" && info.Error.Length == 0, info.Error);
        Assert.Equal([25565, 3074], info.Mappings.Select(m => m.ExternalPort));
        Assert.Equal(3, fake.Calls.Count(c => c == "GetGenericPortMappingEntry"));
    }

    [Fact]
    public void RouterFindings()
    {
        var info = new RouterInfo { Found = true, FriendlyName = "Smart Hub 2", ExternalIp = "100.70.1.2" };
        info.Mappings.Add(new PortMapping { ExternalPort = 25565, Protocol = "TCP", InternalClient = "192.168.1.71", InternalPort = 25565, Description = "Minecraft server" });
        info.Mappings.Add(new PortMapping { ExternalPort = 3074, Protocol = "UDP", InternalClient = "192.168.1.40", InternalPort = 3074, Description = "Xbox" });
        var fs = Inventory.RouterFindings(info.ToJson(), ["192.168.1.71"], []).ToDictionary(f => f.Id);
        Assert.Equal(Severity.Critical, fs["router.forward.TCP.25565"].Severity);
        Assert.Equal(Severity.High, fs["router.forward.UDP.3074"].Severity);
        Assert.Equal(Severity.Low, fs["router.upnp_on"].Severity);
        Assert.Equal(Severity.Info, fs["router.cgnat"].Severity);
        var kept = Inventory.RouterFindings(info.ToJson(), ["192.168.1.71"], new() { ["keep:router.forward.TCP.25565"] = 1 }).ToDictionary(f => f.Id);
        Assert.Equal(FindingStatus.Accepted, kept["router.forward.TCP.25565"].Status);
        var none = Inventory.RouterFindings(new JsonObject { ["found"] = false }, [], []);
        Assert.True(none[0].Id == "router.upnp_not_found" && none[0].Severity == Severity.Info);
    }

    [Fact]
    public void DeviceFindingsAndNewDevices()
    {
        var kb = KnowledgeBase.Get();
        var cam = new Device { Ip = "192.168.1.20", Mac = "AC:DE:48:00:11:22", Vendor = "Hikvision", OpenPorts = [23, 80, 554], New = true };
        var router = new Device { Ip = "192.168.1.254", Mac = "AA:BB:CC:00:00:01", OpenPorts = [53, 80, 443], IsGateway = true };
        var phone = new Device { Ip = "192.168.1.30", Mac = "DA:A1:19:00:00:01", New = true };
        var fs = Inventory.DeviceFindings([cam, router, phone], kb, firstScan: false).ToDictionary(f => f.Id);
        var telnet = fs["lan.services.AC:DE:48:00:11:22"];
        Assert.True(telnet.Severity == Severity.High && telnet.Title.Contains("Telnet", StringComparison.Ordinal));
        Assert.Empty(telnet.Fixes);
        Assert.False(fs.ContainsKey("lan.services.AA:BB:CC:00:00:01"));
        Assert.True(fs.ContainsKey("lan.new_device.DA:A1:19:00:00:01"));
        Assert.DoesNotContain(Inventory.DeviceFindings([cam, phone], kb, firstScan: true), f => f.Id.StartsWith("lan.new_device", StringComparison.Ordinal));
    }

    [Fact]
    public void InventoryStore()
    {
        using var tmp = new TempDir();
        var h = new History(tmp.File("h.db"));
        Assert.True(h.UpsertDevice("AA:BB:CC:00:00:01", "192.168.1.5", "tv", "LG", []));
        Assert.False(h.UpsertDevice("AA:BB:CC:00:00:01", "192.168.1.6", "", "", new JsonObject { ["open_ports"] = new JsonArray(8008) }));
        h.SetDeviceTrusted("AA:BB:CC:00:00:01", true);
        var d = h.Devices()[0];
        Assert.True(Js.Str(d["ip"]) == "192.168.1.6" && Js.Str(d["name"]) == "tv" && Js.Truthy(d["trusted"]));
        Assert.Equal(8008, Js.Int(d["data"]!["open_ports"]![0]));
    }

    [Fact]
    public void ReportEscapesUntrustedNamesAndHasSections()
    {
        var raw = RawScan.FromJson(Golden.Fixture("this_pc_raw.json"));
        var result = Analysis.Analyze(raw);
        result.Extras["devices"] = new JsonArray(new Device { Ip = "192.168.1.9", Mac = "AA:BB:CC:00:00:09", Label = "<script>alert(1)</script>" }.ToJson());
        result.Extras["router"] = new JsonObject
        {
            ["found"] = true, ["friendly_name"] = "<img src=x onerror=alert(1)>", ["external_ip"] = "81.2.69.142",
            ["mappings"] = new JsonArray(new JsonObject { ["protocol"] = "TCP", ["external_port"] = 1, ["internal_client"] = "x", ["internal_port"] = 1, ["description"] = "<b>evil</b>" }),
        };
        var html = HtmlReport.Render(result, trend: [("2026-11-01", 40), ("2026-11-02", 35)]);
        Assert.DoesNotContain("<script>alert", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<img src=x", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<b>evil</b>", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
        foreach (var section in new[] { "Findings by control area", "Firewalls", "Malware protection", "Ports other devices can reach", "<polyline", "Changes made by SimplySec" })
        {
            Assert.Contains(section, html, StringComparison.Ordinal);
        }
    }
}
