using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.InteropServices;
using SimplySec.Core.Compat;

namespace SimplySec.Windows.Interop;

/// <summary>A socket from the TCP/UDP owner tables (what psutil.net_connections reads).</summary>
internal readonly record struct SocketEntry(string Protocol, string LocalIp, int LocalPort, string RemoteIp, int RemotePort, int State, int Pid);

/// <summary>GetExtendedTcpTable / GetExtendedUdpTable for IPv4 and IPv6.</summary>
internal static partial class IpHelper
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const int ErrorInsufficientBuffer = 122;
    public const int MibTcpStateListen = 2;
    public const int MibTcpStateEstab = 5;

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedTcpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order, int af, int tableClass, int reserved);

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedUdpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order, int af, int tableClass, int reserved);

    private delegate uint TableFn(IntPtr table, ref int size, bool order, int af, int cls, int reserved);

    private static byte[] Read(bool tcp, int af)
    {
        var size = 0;
        for (var attempt = 0; attempt < 8; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(Math.Max(size, 4));
            try
            {
                var rc = tcp
                    ? GetExtendedTcpTable(buffer, ref size, false, af, TcpTableOwnerPidAll, 0)
                    : GetExtendedUdpTable(buffer, ref size, false, af, UdpTableOwnerPid, 0);
                if (rc == ErrorInsufficientBuffer)
                {
                    continue;
                }
                if (rc != 0)
                {
                    throw new System.ComponentModel.Win32Exception((int)rc);
                }
                var bytes = new byte[size];
                Marshal.Copy(buffer, bytes, 0, size);
                return bytes;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        throw new InvalidOperationException("socket table kept growing");
    }

    private static int Port(ReadOnlySpan<byte> b) => BinaryPrimitives.ReadUInt16BigEndian(b[..2]);

    private static string V4(ReadOnlySpan<byte> b) => $"{b[0]}.{b[1]}.{b[2]}.{b[3]}";

    private static string V6(ReadOnlySpan<byte> b)
    {
        BigInteger v = 0;
        foreach (var x in b[..16])
        {
            v = (v << 8) | x;
        }
        return PyIp.Format(6, v);
    }

    /// <summary>All TCP sockets (every state) and all UDP endpoints, IPv4 then IPv6.</summary>
    public static List<SocketEntry> AllSockets()
    {
        var output = new List<SocketEntry>();
        // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid (6 DWORDs)
        var t4 = Read(true, AfInet);
        var n = BitConverter.ToInt32(t4, 0);
        for (var i = 0; i < n; i++)
        {
            var row = t4.AsSpan(4 + i * 24, 24);
            output.Add(new SocketEntry("tcp", V4(row[4..]), Port(row[8..]), V4(row[12..]), Port(row[16..]),
                BitConverter.ToInt32(row[..4]), BitConverter.ToInt32(row[20..24])));
        }
        // MIB_TCP6ROW_OWNER_PID: localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, pid
        var t6 = Read(true, AfInet6);
        n = BitConverter.ToInt32(t6, 0);
        for (var i = 0; i < n; i++)
        {
            var row = t6.AsSpan(4 + i * 56, 56);
            output.Add(new SocketEntry("tcp", V6(row), Port(row[20..]), V6(row[24..]), Port(row[44..]),
                BitConverter.ToInt32(row[48..52]), BitConverter.ToInt32(row[52..56])));
        }
        // MIB_UDPROW_OWNER_PID: localAddr, localPort, pid
        var u4 = Read(false, AfInet);
        n = BitConverter.ToInt32(u4, 0);
        for (var i = 0; i < n; i++)
        {
            var row = u4.AsSpan(4 + i * 12, 12);
            output.Add(new SocketEntry("udp", V4(row), Port(row[4..]), "", 0, 0, BitConverter.ToInt32(row[8..12])));
        }
        // MIB_UDP6ROW_OWNER_PID: localAddr[16], localScope, localPort, pid
        var u6 = Read(false, AfInet6);
        n = BitConverter.ToInt32(u6, 0);
        for (var i = 0; i < n; i++)
        {
            var row = u6.AsSpan(4 + i * 28, 28);
            output.Add(new SocketEntry("udp", V6(row), Port(row[20..]), "", 0, 0, BitConverter.ToInt32(row[24..28])));
        }
        return output;
    }
}
