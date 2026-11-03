using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Serilog;
using SimplySec.Core.Actions;
using SimplySec.Core.Compat;
using SimplySec.Core.Eval;
using SimplySec.Core.Model;
using SimplySec.Windows.Interop;

namespace SimplySec.Windows;

public sealed class FirewallException(string message) : Exception(message);

/// <summary>
/// Windows Defender Firewall through typed COM (INetFwPolicy2). Every rule SimplySec creates
/// carries Grouping "SimplySec" and a name "SimplySec:&lt;fix&gt;:&lt;id&gt;".
/// </summary>
public sealed class Firewall : IFirewallAdapter
{
    public const string Group = "SimplySec";
    private const int DirIn = 1;
    private const int ActionBlock = 0;
    private const int ActionAllow = 1;

    private static string ComMessage(Exception exc)
    {
        if (exc is COMException or UnauthorizedAccessException)
        {
            var hr = exc.HResult;
            if (hr == unchecked((int)0x80070005))
            {
                return "access denied (administrator rights are needed)";
            }
            return $"COM error 0x{hr:x8}";
        }
        return exc.Message;
    }

    private static T Com<T>(string what, Func<T> fn)
    {
        try
        {
            return fn();
        }
        catch (FirewallException)
        {
            throw;
        }
        catch (Exception exc)
        {
            throw new FirewallException($"{what}: {ComMessage(exc)}");
        }
    }

    // ------------------------------------------------------------------ read

    private static T Get<T>(Func<T> getter, T def)
    {
        try
        {
            var v = getter();
            return v is null ? def : v;
        }
        catch (Exception)
        {
            return def;
        }
    }

    private static string OrStar(string s) => string.IsNullOrEmpty(s) ? "*" : s;

    internal static FirewallRule RuleFromCom(INetFwRule3 r)
    {
        var interfaces = Get<object?>(r.get_Interfaces, null);
        var ifaceList = interfaces is object[] arr ? arr.Select(i => Convert.ToString(i, CultureInfo.InvariantCulture) ?? "").ToList() : [];
        return new FirewallRule
        {
            Name = Get(r.get_Name, ""),
            Description = Get(r.get_Description, ""),
            Application = Get(r.get_ApplicationName, ""),
            Service = Get(r.get_serviceName, ""),
            Protocol = Get(r.get_Protocol, 256),
            LocalPorts = OrStar(Get(r.get_LocalPorts, "")),
            RemotePorts = OrStar(Get(r.get_RemotePorts, "")),
            LocalAddresses = OrStar(Get(r.get_LocalAddresses, "")),
            RemoteAddresses = OrStar(Get(r.get_RemoteAddresses, "")),
            IcmpTypes = Get(r.get_IcmpTypesAndCodes, ""),
            Direction = Get(r.get_Direction, 1) == DirIn ? "in" : "out",
            Interfaces = ifaceList,
            InterfaceTypes = string.IsNullOrEmpty(Get(r.get_InterfaceTypes, "")) ? "All" : r.get_InterfaceTypes(),
            Enabled = Get(r.get_Enabled, false),
            Grouping = Get(r.get_Grouping, ""),
            Profiles = Get(r.get_Profiles, EnumText.AllProfilesMask),
            EdgeTraversal = Get(r.get_EdgeTraversal, false),
            Action = Get(r.get_Action, 1) == ActionAllow ? "allow" : "block",
            EdgeTraversalOptions = Get(r.get_EdgeTraversalOptions, 0),
            LocalAppPackageId = Get(r.get_LocalAppPackageId, ""),
            LocalUserOwner = Get(r.get_LocalUserOwner, ""),
            LocalUserAuthorized = Get(r.get_LocalUserAuthorizedList, ""),
            RemoteUserAuthorized = Get(r.get_RemoteUserAuthorizedList, ""),
            RemoteMachineAuthorized = Get(r.get_RemoteMachineAuthorizedList, ""),
            SecureFlags = Get(r.get_SecureFlags, 0),
        };
    }

    private static readonly string[] RuleStores =
    [
        @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
        @"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules",
    ];

    /// <summary>Resolve '@FirewallAPI.dll,-28511' to the display name Windows shows (and COM returns).</summary>
    private static string Indirect(string text)
    {
        if (!text.StartsWith('@'))
        {
            return text;
        }
        var sb = new StringBuilder(1024);
        return Native.SHLoadIndirectString(text, sb, sb.Capacity, IntPtr.Zero) == 0 ? sb.ToString() : text;
    }

    private static readonly Dictionary<string, int> ProfileBits = new(StringComparer.Ordinal) { ["domain"] = 1, ["private"] = 2, ["public"] = 4 };

    private static readonly Lazy<Dictionary<string, string>> ProcessEnv = new(() =>
    {
        var env = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (System.Collections.DictionaryEntry kv in Environment.GetEnvironmentVariables())
        {
            env[PyStr.Upper((string)kv.Key)] = (string?)kv.Value ?? "";
        }
        return env;
    });

    private static (string, int, string, string, int, string) Shape(string direction, int protocol, string app, string service, int profiles, string action)
    {
        var mask = profiles is 0 or EnumText.AllProfilesMask ? 7 : profiles & 7;
        return (direction, protocol, Evaluator.NormalizeAppPath(app, ProcessEnv.Value), PyStr.Lower(service), mask, action);
    }

    /// <summary>
    /// Hidden trust-tuple (TTK) conditions from the rules' registry definitions, joined to the COM
    /// rules by name, or by shape when that shape is unique.
    /// </summary>
    internal sealed class TrustTupleIndex
    {
        public Dictionary<(string, (string, int, string, string, int, string)), List<string>> ByName { get; } = [];
        public Dictionary<(string, int, string, string, int, string), List<List<string>>> ByShape { get; } = [];

        public List<string> Lookup(FirewallRule rule)
        {
            var shape = Shape(rule.Direction, rule.Protocol, rule.Application, rule.Service, rule.Profiles, rule.Action);
            if (ByName.TryGetValue((PyStr.Lower(rule.Name), shape), out var hit))
            {
                return hit;
            }
            return ByShape.TryGetValue(shape, out var candidates) && candidates.Count == 1 ? candidates[0] : [];
        }
    }

    internal static TrustTupleIndex BuildTrustTupleIndex()
    {
        var index = new TrustTupleIndex();
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        foreach (var sub in RuleStores)
        {
            using var key = hklm.OpenSubKey(sub);
            if (key is null)
            {
                continue;
            }
            foreach (var valueName in key.GetValueNames())
            {
                if (key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string value || !value.StartsWith("v2", StringComparison.Ordinal))
                {
                    continue;
                }
                var fields = new Dictionary<string, string>(StringComparer.Ordinal);
                var ttk = new List<string>();
                var profiles = 0;
                foreach (var part in value.Split('|'))
                {
                    var eq = part.IndexOf('=');
                    var k = eq >= 0 ? part[..eq] : part;
                    var v = eq >= 0 ? part[(eq + 1)..] : "";
                    if (k.StartsWith("TTK", StringComparison.Ordinal))
                    {
                        ttk.Add(v);
                    }
                    else if (k == "Profile")
                    {
                        profiles |= ProfileBits.GetValueOrDefault(PyStr.Lower(v), 0);
                    }
                    else
                    {
                        fields.TryAdd(k, v);
                    }
                }
                var direction = PyStr.Lower(fields.GetValueOrDefault("Dir", "In")) == "in" ? "in" : "out";
                var protoText = fields.GetValueOrDefault("Protocol", "256");
                var proto = string.IsNullOrEmpty(protoText) ? 256 : int.Parse(protoText, CultureInfo.InvariantCulture);
                var action = PyStr.Lower(fields.GetValueOrDefault("Action", "Allow")) == "allow" ? "allow" : "block";
                var shape = Shape(direction, proto, fields.GetValueOrDefault("App", ""), fields.GetValueOrDefault("Svc", ""), profiles, action);
                if (!index.ByShape.TryGetValue(shape, out var list))
                {
                    list = [];
                    index.ByShape[shape] = list;
                }
                list.Add(ttk);
                if (ttk.Count > 0)
                {
                    index.ByName[(PyStr.Lower(Indirect(fields.GetValueOrDefault("Name", ""))), shape)] = ttk;
                }
            }
        }
        return index;
    }

    /// <summary>True when Group Policy sets the firewall state or default action.</summary>
    private static bool PolicyManaged()
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        foreach (var sub in new[] { "DomainProfile", "PrivateProfile", "PublicProfile", "StandardProfile" })
        {
            using var k = hklm.OpenSubKey($@"SOFTWARE\Policies\Microsoft\WindowsFirewall\{sub}");
            if (k is not null && (k.GetValue("EnableFirewall") is not null || k.GetValue("DefaultInboundAction") is not null))
            {
                return true;
            }
        }
        return false;
    }

    private static List<INetFwRule3> AllComRules(INetFwPolicy2 fw) =>
        FirewallCom.Enumerate(fw.get_Rules()).Select(o => (INetFwRule3)o).ToList();

    public static FirewallState ReadState(bool includeRules = true) => Com("reading the firewall", () =>
    {
        var fw = FirewallCom.CreatePolicy();
        var state = new FirewallState();
        foreach (var p in EnumText.SingleProfiles)
        {
            state.Profiles[p] = new FirewallProfileState
            {
                Profile = p,
                Enabled = fw.get_FirewallEnabled((int)p),
                DefaultInboundBlock = fw.get_DefaultInboundAction((int)p) == ActionBlock,
                BlockAllInbound = fw.get_BlockAllInboundTraffic((int)p),
            };
        }
        if (includeRules)
        {
            state.Rules = AllComRules(fw).Select(RuleFromCom).ToList();
            if (state.Rules.Count > 0)
            {
                TrustTupleIndex? ttk = null;
                try
                {
                    ttk = BuildTrustTupleIndex();
                }
                catch (Exception exc)
                {
                    Log.Warning("could not read trust-tuple conditions: {Error}", exc.Message);
                }
                foreach (var r in state.Rules)
                {
                    var hit = ttk?.Lookup(r) ?? [];
                    if (hit.Count > 0)
                    {
                        r.TrustTuples = [.. hit];
                    }
                }
            }
        }
        state.CurrentProfiles = fw.get_CurrentProfileTypes();
        state.ManagedByPolicy = PolicyManaged();
        state.LocalPolicyModifyState = fw.get_LocalPolicyModifyState();
        return state;
    });

    public List<FirewallRule> FindRules(string name) => Com($"looking up rule '{name}'", () =>
        AllComRules(FirewallCom.CreatePolicy()).Where(r => r.get_Name() == name).Select(RuleFromCom).ToList());

    public List<FirewallRule> GroupRules(string group = Group) => Com("listing SimplySec rules", () =>
        AllComRules(FirewallCom.CreatePolicy()).Where(r => (r.get_Grouping() ?? "") == group).Select(RuleFromCom).ToList());

    // ------------------------------------------------------------------ write

    /// <summary>Create one rule exactly as described (property order as v2; Enabled last).</summary>
    public void AddRule(FirewallRule rule) => Com($"creating rule '{rule.Name}'", () =>
    {
        var fw = FirewallCom.CreatePolicy();
        var r = FirewallCom.CreateRule();
        r.put_Name(rule.Name);
        r.put_Description(rule.Description);
        if (rule.Application.Length > 0)
        {
            r.put_ApplicationName(rule.Application);
        }
        if (rule.Service.Length > 0)
        {
            r.put_serviceName(rule.Service);
        }
        r.put_Protocol(rule.Protocol); // must precede ports
        if (rule.Protocol is 6 or 17)
        {
            if (rule.LocalPorts is not ("" or "*"))
            {
                r.put_LocalPorts(rule.LocalPorts);
            }
            if (rule.RemotePorts is not ("" or "*"))
            {
                r.put_RemotePorts(rule.RemotePorts);
            }
        }
        if (rule.LocalAddresses is not ("" or "*"))
        {
            r.put_LocalAddresses(rule.LocalAddresses);
        }
        if (rule.RemoteAddresses is not ("" or "*"))
        {
            r.put_RemoteAddresses(rule.RemoteAddresses);
        }
        if (rule.IcmpTypes.Length > 0)
        {
            r.put_IcmpTypesAndCodes(rule.IcmpTypes);
        }
        r.put_Direction(rule.Direction == "in" ? DirIn : 2);
        if (rule.Interfaces.Count > 0)
        {
            r.put_Interfaces(rule.Interfaces.Cast<object>().ToArray());
        }
        r.put_InterfaceTypes(string.IsNullOrEmpty(rule.InterfaceTypes) ? "All" : rule.InterfaceTypes);
        r.put_Profiles(rule.Profiles);
        r.put_Action(rule.Action == "allow" ? ActionAllow : ActionBlock);
        r.put_EdgeTraversal(rule.EdgeTraversal);
        if (rule.Grouping.Length > 0)
        {
            r.put_Grouping(rule.Grouping);
        }
        if (rule.LocalAppPackageId.Length > 0)
        {
            r.put_LocalAppPackageId(rule.LocalAppPackageId);
        }
        if (rule.LocalUserOwner.Length > 0)
        {
            r.put_LocalUserOwner(rule.LocalUserOwner);
        }
        if (rule.LocalUserAuthorized.Length > 0)
        {
            r.put_LocalUserAuthorizedList(rule.LocalUserAuthorized);
        }
        if (rule.RemoteUserAuthorized.Length > 0)
        {
            r.put_RemoteUserAuthorizedList(rule.RemoteUserAuthorized);
        }
        if (rule.RemoteMachineAuthorized.Length > 0)
        {
            r.put_RemoteMachineAuthorizedList(rule.RemoteMachineAuthorized);
        }
        if (rule.EdgeTraversalOptions != 0)
        {
            r.put_EdgeTraversalOptions(rule.EdgeTraversalOptions);
        }
        r.put_Enabled(rule.Enabled); // COM default is disabled
        fw.get_Rules().Add((INetFwRule)r);
        Log.Information("firewall rule added: {Name}", rule.Name);
        return 0;
    });

    /// <summary>Remove every rule with exactly this name.</summary>
    public void RemoveRulesNamed(string name) => Com($"removing rule '{name}'", () =>
    {
        var fw = FirewallCom.CreatePolicy();
        var removed = 0;
        while (removed < 50 && AllComRules(fw).Any(r => r.get_Name() == name))
        {
            fw.get_Rules().Remove(name);
            removed++;
        }
        Log.Information("firewall rule removed: {Name} (x{Count})", name, removed);
        return removed;
    });

    public void SetProfile(Profile profile, bool? enabled = null, bool? defaultInboundBlock = null) =>
        Com($"changing the {profile.Label()} firewall profile", () =>
        {
            var fw = FirewallCom.CreatePolicy();
            if (enabled is not null)
            {
                fw.put_FirewallEnabled((int)profile, enabled.Value);
            }
            if (defaultInboundBlock is not null)
            {
                fw.put_DefaultInboundAction((int)profile, defaultInboundBlock.Value ? ActionBlock : ActionAllow);
            }
            return 0;
        });

    public FirewallProfileState ReadProfile(Profile profile) => ReadState(includeRules: false).Profiles[profile];

    /// <summary>netsh advfirewall export to a unique timestamped file; keep the newest 10.</summary>
    public string ExportPolicy(string backupsDir)
    {
        Directory.CreateDirectory(backupsDir);
        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss-ffffff", CultureInfo.InvariantCulture);
        var target = Path.Combine(backupsDir, $"firewall-{stamp}.wfw");
        Runner.Run([Path.Combine(Runner.System32, "netsh.exe"), "advfirewall", "export", target], timeout: 60, check: true);
        if (!File.Exists(target))
        {
            throw new FirewallException($"netsh reported success but {target} was not written");
        }
        var backups = Directory.GetFiles(backupsDir, "firewall-*.wfw").Order(StringComparer.Ordinal).ToList();
        foreach (var old in backups.Take(Math.Max(0, backups.Count - 10)))
        {
            try
            {
                File.Delete(old);
            }
            catch (IOException)
            {
                Log.Warning("could not delete old backup {Path}", old);
            }
        }
        return target;
    }
}
