using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace SimplySec.Windows.Interop;

// Typed COM interop for Windows Defender Firewall (netfw.h). Vtable order matters: methods are
// declared exactly in the order of the C++ interfaces, after IDispatch.

[ComImport]
[Guid("98325047-C671-4174-8D81-DEFCD3F03186")]
[InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface INetFwPolicy2
{
    int get_CurrentProfileTypes();
    [return: MarshalAs(UnmanagedType.VariantBool)] bool get_FirewallEnabled(int profileType);
    void put_FirewallEnabled(int profileType, [MarshalAs(UnmanagedType.VariantBool)] bool enabled);
    object get_ExcludedInterfaces(int profileType);
    void put_ExcludedInterfaces(int profileType, object interfaces);
    [return: MarshalAs(UnmanagedType.VariantBool)] bool get_BlockAllInboundTraffic(int profileType);
    void put_BlockAllInboundTraffic(int profileType, [MarshalAs(UnmanagedType.VariantBool)] bool block);
    [return: MarshalAs(UnmanagedType.VariantBool)] bool get_NotificationsDisabled(int profileType);
    void put_NotificationsDisabled(int profileType, [MarshalAs(UnmanagedType.VariantBool)] bool disabled);
    [return: MarshalAs(UnmanagedType.VariantBool)] bool get_UnicastResponsesToMulticastBroadcastDisabled(int profileType);
    void put_UnicastResponsesToMulticastBroadcastDisabled(int profileType, [MarshalAs(UnmanagedType.VariantBool)] bool disabled);
    INetFwRules get_Rules();
    [return: MarshalAs(UnmanagedType.IUnknown)] object get_ServiceRestriction();
    void EnableRuleGroup(int profileTypesBitmask, [MarshalAs(UnmanagedType.BStr)] string group, [MarshalAs(UnmanagedType.VariantBool)] bool enable);
    [return: MarshalAs(UnmanagedType.VariantBool)] bool IsRuleGroupEnabled(int profileTypesBitmask, [MarshalAs(UnmanagedType.BStr)] string group);
    void RestoreLocalFirewallDefaults();
    int get_DefaultInboundAction(int profileType);
    void put_DefaultInboundAction(int profileType, int action);
    int get_DefaultOutboundAction(int profileType);
    void put_DefaultOutboundAction(int profileType, int action);
    [return: MarshalAs(UnmanagedType.VariantBool)] bool get_IsRuleGroupCurrentlyEnabled([MarshalAs(UnmanagedType.BStr)] string group);
    int get_LocalPolicyModifyState();
}

[ComImport]
[Guid("9C4C6277-5027-441E-AFAE-CA1F542DA009")]
[InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface INetFwRules
{
    int get_Count();
    void Add(INetFwRule rule);
    void Remove([MarshalAs(UnmanagedType.BStr)] string name);
    INetFwRule Item([MarshalAs(UnmanagedType.BStr)] string name);
    [return: MarshalAs(UnmanagedType.IUnknown)] object get__NewEnum();
}

[ComImport]
[Guid("AF230D27-BABA-4E42-ACED-F524F22CFCE2")]
[InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface INetFwRule
{
    [return: MarshalAs(UnmanagedType.BStr)] string get_Name();
    void put_Name([MarshalAs(UnmanagedType.BStr)] string v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_Description();
    void put_Description([MarshalAs(UnmanagedType.BStr)] string v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_ApplicationName();
    void put_ApplicationName([MarshalAs(UnmanagedType.BStr)] string v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_serviceName();
    void put_serviceName([MarshalAs(UnmanagedType.BStr)] string v);
    int get_Protocol();
    void put_Protocol(int v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_LocalPorts();
    void put_LocalPorts([MarshalAs(UnmanagedType.BStr)] string v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_RemotePorts();
    void put_RemotePorts([MarshalAs(UnmanagedType.BStr)] string v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_LocalAddresses();
    void put_LocalAddresses([MarshalAs(UnmanagedType.BStr)] string v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_RemoteAddresses();
    void put_RemoteAddresses([MarshalAs(UnmanagedType.BStr)] string v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_IcmpTypesAndCodes();
    void put_IcmpTypesAndCodes([MarshalAs(UnmanagedType.BStr)] string v);
    int get_Direction();
    void put_Direction(int v);
    object get_Interfaces();
    void put_Interfaces(object v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_InterfaceTypes();
    void put_InterfaceTypes([MarshalAs(UnmanagedType.BStr)] string v);
    [return: MarshalAs(UnmanagedType.VariantBool)] bool get_Enabled();
    void put_Enabled([MarshalAs(UnmanagedType.VariantBool)] bool v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_Grouping();
    void put_Grouping([MarshalAs(UnmanagedType.BStr)] string v);
    int get_Profiles();
    void put_Profiles(int v);
    [return: MarshalAs(UnmanagedType.VariantBool)] bool get_EdgeTraversal();
    void put_EdgeTraversal([MarshalAs(UnmanagedType.VariantBool)] bool v);
    int get_Action();
    void put_Action(int v);
}

[ComImport]
[Guid("B21563FF-D696-4222-AB46-4E89B73AB34A")]
[InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface INetFwRule3
{
    // INetFwRule
    [return: MarshalAs(UnmanagedType.BStr)] string get_Name();
    void put_Name([MarshalAs(UnmanagedType.BStr)] string v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_Description();
    void put_Description([MarshalAs(UnmanagedType.BStr)] string v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_ApplicationName();
    void put_ApplicationName([MarshalAs(UnmanagedType.BStr)] string v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_serviceName();
    void put_serviceName([MarshalAs(UnmanagedType.BStr)] string v);
    int get_Protocol();
    void put_Protocol(int v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_LocalPorts();
    void put_LocalPorts([MarshalAs(UnmanagedType.BStr)] string v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_RemotePorts();
    void put_RemotePorts([MarshalAs(UnmanagedType.BStr)] string v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_LocalAddresses();
    void put_LocalAddresses([MarshalAs(UnmanagedType.BStr)] string v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_RemoteAddresses();
    void put_RemoteAddresses([MarshalAs(UnmanagedType.BStr)] string v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_IcmpTypesAndCodes();
    void put_IcmpTypesAndCodes([MarshalAs(UnmanagedType.BStr)] string v);
    int get_Direction();
    void put_Direction(int v);
    object get_Interfaces();
    void put_Interfaces(object v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_InterfaceTypes();
    void put_InterfaceTypes([MarshalAs(UnmanagedType.BStr)] string v);
    [return: MarshalAs(UnmanagedType.VariantBool)] bool get_Enabled();
    void put_Enabled([MarshalAs(UnmanagedType.VariantBool)] bool v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_Grouping();
    void put_Grouping([MarshalAs(UnmanagedType.BStr)] string v);
    int get_Profiles();
    void put_Profiles(int v);
    [return: MarshalAs(UnmanagedType.VariantBool)] bool get_EdgeTraversal();
    void put_EdgeTraversal([MarshalAs(UnmanagedType.VariantBool)] bool v);
    int get_Action();
    void put_Action(int v);
    // INetFwRule2
    int get_EdgeTraversalOptions();
    void put_EdgeTraversalOptions(int v);
    // INetFwRule3
    [return: MarshalAs(UnmanagedType.BStr)] string get_LocalAppPackageId();
    void put_LocalAppPackageId([MarshalAs(UnmanagedType.BStr)] string v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_LocalUserOwner();
    void put_LocalUserOwner([MarshalAs(UnmanagedType.BStr)] string v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_LocalUserAuthorizedList();
    void put_LocalUserAuthorizedList([MarshalAs(UnmanagedType.BStr)] string v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_RemoteUserAuthorizedList();
    void put_RemoteUserAuthorizedList([MarshalAs(UnmanagedType.BStr)] string v);
    [return: MarshalAs(UnmanagedType.BStr)] string get_RemoteMachineAuthorizedList();
    void put_RemoteMachineAuthorizedList([MarshalAs(UnmanagedType.BStr)] string v);
    int get_SecureFlags();
    void put_SecureFlags(int v);
}

internal static class FirewallCom
{
    public static readonly Guid PolicyClsid = new("E2B3C97F-6AE1-41AC-817A-F6F92166D7DD");
    public static readonly Guid RuleClsid = new("2C5BC43E-3369-4C33-AB0C-BE9469677AF4");

    public static INetFwPolicy2 CreatePolicy() =>
        (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromCLSID(PolicyClsid, throwOnError: true)!)!;

    public static INetFwRule3 CreateRule() =>
        (INetFwRule3)Activator.CreateInstance(Type.GetTypeFromCLSID(RuleClsid, throwOnError: true)!)!;

    /// <summary>Enumerates the rule collection through its IEnumVARIANT.</summary>
    public static IEnumerable<object> Enumerate(INetFwRules rules)
    {
        var enumerator = (IEnumVARIANT)rules.get__NewEnum();
        var buffer = new object[1];
        while (true)
        {
            var hr = enumerator.Next(1, buffer, IntPtr.Zero);
            if (hr != 0 || buffer[0] is null)
            {
                yield break;
            }
            yield return buffer[0];
            buffer[0] = null!;
        }
    }
}
