using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using SimplySec.Core.Actions;
using SimplySec.Core.Compat;
using SimplySec.Core.Model;

namespace SimplySec.Windows;

/// <summary>
/// Network adapters, addresses and firewall profiles (port of windows/network.py). Addresses come
/// from GetAdaptersAddresses (what psutil reads); type, profile, gateways and DNS from facts.
/// </summary>
public sealed partial class Network : INetworkAdapter
{
    private static readonly Dictionary<long, Profile> CategoryToProfile = new() { [0] = Profile.Public, [1] = Profile.Private, [2] = Profile.Domain };

    private static readonly string[] VpnHints = ["tailscale", "wireguard", "openvpn", "tap-windows", "zerotier", "wintun", "vpn", "nordlynx", "fortinet", "cisco anyconnect"];
    private static readonly string[] VirtualHints = ["vmware", "virtualbox", "hyper-v", "vethernet", "virtual ethernet", "wsl", "docker"];

    public static InterfaceKind Classify(JsonNode? adapter, string alias)
    {
        if (adapter is null)
        {
            return PyStr.Lower(alias).Contains("loopback", StringComparison.Ordinal) ? InterfaceKind.Loopback : InterfaceKind.Other;
        }
        var text = PyStr.Lower($"{Js.Str(Js.Get(adapter, "name"))} {Js.Str(Js.Get(adapter, "description"))}");
        var ifType = Js.Truthy(Js.Get(adapter, "if_type")) ? Js.Int(Js.Get(adapter, "if_type")) : 0;
        if (ifType == 24)
        {
            return InterfaceKind.Loopback;
        }
        if (ifType == 71 || (Js.Truthy(Js.Get(adapter, "medium")) ? Js.Int(Js.Get(adapter, "medium")) : 0) == 9)
        {
            return InterfaceKind.Wifi;
        }
        if (ifType is 23 or 53 or 131 || VpnHints.Any(h => text.Contains(h, StringComparison.Ordinal)))
        {
            return VirtualHints.Any(h => text.Contains(h, StringComparison.Ordinal)) ? InterfaceKind.Virtual : InterfaceKind.Vpn;
        }
        if (Js.Truthy(Js.Get(adapter, "virtual")) || VirtualHints.Any(h => text.Contains(h, StringComparison.Ordinal)))
        {
            return InterfaceKind.Virtual;
        }
        return InterfaceKind.Ethernet;
    }

    private static string FormatAddress(System.Net.IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        BigInteger v = 0;
        foreach (var b in bytes)
        {
            v = (v << 8) | b;
        }
        return PyIp.Format(bytes.Length == 4 ? 4 : 6, v);
    }

    /// <summary>psutil.net_if_addrs + net_if_stats: friendly name → (addresses "ip/prefix", MAC, up).</summary>
    internal static List<(string Alias, List<string> Addresses, string Mac, bool Up)> LocalInterfaces()
    {
        var output = new List<(string, List<string>, string, bool)>();
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            var mac = ni.GetPhysicalAddress().GetAddressBytes();
            var macText = mac.Length > 0 ? string.Join('-', mac.Select(b => b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture))) : "";
            var addresses = new List<string>();
            foreach (var ua in ni.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                {
                    addresses.Add($"{FormatAddress(ua.Address)}/{ua.PrefixLength}");
                }
                else if (ua.Address.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    // psutil reports no IPv6 netmask, so v2 stored every IPv6 address as /128.
                    addresses.Add($"{FormatAddress(ua.Address)}/128");
                }
            }
            if (macText.Length == 0 && addresses.Count == 0)
            {
                continue;
            }
            output.Add((ni.Name, addresses, macText, ni.OperationalStatus == OperationalStatus.Up));
        }
        return output;
    }

    /// <summary>Combine the local adapters with the facts.ps1 network section.</summary>
    public static List<NetInterface> BuildInterfaces(JsonNode? networkFact)
    {
        var net = networkFact ?? new JsonObject();
        var adapters = new Dictionary<string, JsonNode>(StringComparer.Ordinal);
        foreach (var a in Js.AsList(Js.Get(net, "adapters")))
        {
            adapters[Js.Str(Js.Get(a, "name"))] = a!;
        }
        Dictionary<long, JsonNode> ByIndex(string key)
        {
            var d = new Dictionary<long, JsonNode>();
            foreach (var x in Js.AsList(Js.Get(net, key)))
            {
                if (!Js.IsNull(Js.Get(x, "index")))
                {
                    d[Js.Long(Js.Get(x, "index"))] = x!;
                }
            }
            return d;
        }
        var profiles = ByIndex("profiles");
        var ipcfg = ByIndex("ip");
        var cfg = ByIndex("config");
        var output = new List<NetInterface>();
        foreach (var (alias, addresses, mac, up) in LocalInterfaces())
        {
            adapters.TryGetValue(alias, out var adapter);
            var index = adapter is not null ? Js.Int(adapter["index"]) : -1;
            profiles.TryGetValue(index, out var prof);
            ipcfg.TryGetValue(index, out var ipc);
            cfg.TryGetValue(index, out var c);
            var adapterMac = adapter is not null ? Js.Get(adapter, "mac") : null;
            Profile? profile = null;
            if (prof is not null && CategoryToProfile.TryGetValue(Js.Long(prof["category"]), out var pp))
            {
                profile = pp;
            }
            output.Add(new NetInterface
            {
                Index = index,
                Alias = alias,
                Description = adapter is not null && Js.Has(adapter, "description") ? Js.Str(adapter["description"]) : "",
                Kind = Classify(adapter, alias),
                Mac = Js.Truthy(adapterMac) ? Js.Str(adapterMac) : mac,
                Up = up,
                Addresses = addresses,
                Profile = profile,
                NetworkName = prof is not null && Js.Has(prof, "name") ? Js.Str(prof["name"]) : "",
                Gateways = Js.AsList(Js.Get(ipc, "gateways")).Where(g => Js.Truthy(g) && Js.Str(g) is not ("0.0.0.0" or "::")).Select(g => Js.Str(g)).ToList(),
                DnsServers = Js.AsList(Js.Get(ipc, "dns")).Where(Js.Truthy).Select(d => Js.Str(d)).ToList(),
                DhcpServers = Js.Truthy(Js.Get(c, "dhcp_server")) ? [Js.Str(c!["dhcp_server"])] : [],
            });
        }
        return output.OrderBy(i => i.Kind == InterfaceKind.Loopback).ThenBy(i => !i.Up).ThenBy(i => i.Alias, StringComparer.Ordinal).ToList();
    }

    public void SetCategory(int index, Profile profile)
    {
        var category = profile switch
        {
            Profile.Public => "Public",
            Profile.Private => "Private",
            _ => throw new ArgumentException("only Public or Private can be set"),
        };
        Runner.PowerShellJson("Set-NetConnectionProfile -InterfaceIndex ([int]$P.index) -NetworkCategory $P.category; 'null'",
            new JsonObject { ["index"] = index, ["category"] = category });
    }

    public Profile? GetCategory(int index)
    {
        var data = Runner.PowerShellJson(
            "$p = Get-NetConnectionProfile -InterfaceIndex ([int]$P.index) -ErrorAction SilentlyContinue; if ($p) { [int]$p.NetworkCategory } else { 'null' }",
            new JsonObject { ["index"] = index });
        return data is not null && !Js.IsNull(data) && CategoryToProfile.TryGetValue(Js.Long(data), out var p) ? p : null;
    }

    // ------------------------------------------------------------------ neighbours (GetIpNetTable2)

    [StructLayout(LayoutKind.Sequential)]
    private struct MibIpNetRow2
    {
        public ushort Family;
        public ushort Port;
        public uint Addr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
        public byte[] Rest;
        public uint InterfaceIndex;
        public ulong InterfaceLuid;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] PhysicalAddress;
        public uint PhysicalAddressLength;
        public uint State;
        public byte Flags;
        public uint ReachabilityTime;
    }

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetIpNetTable2(ushort family, out IntPtr table);

    [LibraryImport("iphlpapi.dll")]
    private static partial void FreeMibTable(IntPtr table);

    /// <summary>IPv4 neighbour (ARP) table for one interface: ip → MAC (Incomplete, zero and broadcast skipped).</summary>
    public static Dictionary<string, string> Neighbors(int interfaceIndex)
    {
        var output = new Dictionary<string, string>(StringComparer.Ordinal);
        if (GetIpNetTable2(2, out var table) != 0)
        {
            throw new System.ComponentModel.Win32Exception();
        }
        try
        {
            var count = Marshal.ReadInt32(table);
            var rowSize = Marshal.SizeOf<MibIpNetRow2>();
            var first = table + IntPtr.Size; // NumEntries is padded to pointer alignment (8)
            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibIpNetRow2>(first + i * rowSize);
                if (row.InterfaceIndex != interfaceIndex || row.State == 1)
                {
                    continue;
                }
                var macBytes = row.PhysicalAddress.Take((int)row.PhysicalAddressLength).ToArray();
                var mac = string.Join(':', macBytes.Select(b => b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture)));
                if (mac.Length == 0 || mac is "00:00:00:00:00:00" or "FF:FF:FF:FF:FF:FF")
                {
                    continue;
                }
                var a = row.Addr;
                output[$"{a & 0xFF}.{(a >> 8) & 0xFF}.{(a >> 16) & 0xFF}.{(a >> 24) & 0xFF}"] = mac;
            }
        }
        finally
        {
            FreeMibTable(table);
        }
        return output;
    }
}
