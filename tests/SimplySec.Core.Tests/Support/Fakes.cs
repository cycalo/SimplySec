using System.Text.Json.Nodes;
using SimplySec.Core.Actions;
using SimplySec.Core.Compat;
using SimplySec.Core.Engine;
using SimplySec.Core.Model;
using SimplySec.Core.Storage;

namespace SimplySec.Core.Tests.Support;

// Fakes with the same method sets as the Python v2 test fakes.

public sealed class FakeFirewall : IFirewallAdapter
{
    public List<FirewallRule> Rules { get; } = [];
    public OrderedDictionary<Profile, FirewallProfileState> Profiles { get; } = new()
    {
        [Profile.Domain] = new FirewallProfileState { Profile = Profile.Domain },
        [Profile.Private] = new FirewallProfileState { Profile = Profile.Private },
        [Profile.Public] = new FirewallProfileState { Profile = Profile.Public },
    };
    public int Exports { get; private set; }
    public List<string> Log { get; } = [];

    public List<FirewallRule> FindRules(string name) => Rules.Where(r => r.Name == name).ToList();

    public void AddRule(FirewallRule rule)
    {
        Log.Add($"add {rule.Name}");
        Rules.Add(rule);
    }

    public void RemoveRulesNamed(string name)
    {
        Log.Add($"remove {name}");
        Rules.RemoveAll(r => r.Name == name);
    }

    public List<FirewallRule> GroupRules(string group = "SimplySec") => Rules.Where(r => r.Grouping == group).ToList();

    public FirewallProfileState ReadProfile(Profile profile) => Profiles[profile];

    public void SetProfile(Profile profile, bool? enabled = null, bool? defaultInboundBlock = null)
    {
        var st = Profiles[profile];
        if (enabled is not null)
        {
            st.Enabled = enabled.Value;
        }
        if (defaultInboundBlock is not null)
        {
            st.DefaultInboundBlock = defaultInboundBlock.Value;
        }
    }

    public string ExportPolicy(string backupsDir)
    {
        Exports++;
        return $"{backupsDir}/firewall-{Exports}.wfw";
    }
}

public sealed class FakeRegistry : IRegistryAdapter
{
    public Dictionary<(string, string), (string Type, JsonNode? Value)> Values { get; } = [];
    public string? FailOn { get; set; }

    public RegSnapshot Read(string path, string name)
    {
        if (Values.TryGetValue((path, name), out var v))
        {
            return new RegSnapshot(true, true, v.Type, v.Value?.DeepClone());
        }
        return new RegSnapshot(Values.Keys.Any(k => k.Item1 == path), false, null, null);
    }

    public void Write(string path, string name, JsonNode? value, string vtype)
    {
        if (FailOn == name)
        {
            throw new UnauthorizedAccessException("access denied");
        }
        Values[(path, name)] = (vtype, value?.DeepClone());
    }

    public void Restore(string path, string name, JsonObject before)
    {
        if (Js.Truthy(before["exists"]))
        {
            Values[(path, name)] = (Js.Str(before["type"]), before["value"]?.DeepClone());
        }
        else
        {
            Values.Remove((path, name));
        }
    }
}

public sealed class FakeSystem : ISystemAdapter
{
    public bool Smb1 { get; set; } = true;
    public JsonObject SmbServerGet() => new() { ["smb1"] = Smb1 };
    public void SmbServerSet(bool smb1) => Smb1 = smb1;
    public JsonObject DefenderGet() => new() { ["controlled_folder_access"] = 0 };
    public void DefenderSetCfa(int mode) { }
    public void UpdateSignatures() { }
    public int NetbiosGet(int configIndex) => 0;
    public void NetbiosSet(int configIndex, int option) { }
    public void CreateRestorePoint(string description) => throw new InvalidOperationException("restore points are off");
}

public sealed class FakeScheduler : ISchedulerAdapter
{
    public Dictionary<string, string> Tasks { get; } = new(StringComparer.Ordinal);
    public string? ExportXml(string name) => Tasks.GetValueOrDefault(name);
    public bool Exists(string name) => Tasks.ContainsKey(name);
    public void Create(string name, string time) => Tasks[name] = $"<Task>SimplySec {time}</Task>";

    public void Restore(string name, string? xml)
    {
        if (!string.IsNullOrEmpty(xml))
        {
            Tasks[name] = xml;
        }
        else
        {
            Tasks.Remove(name);
        }
    }

    public void Delete(string name) => Tasks.Remove(name);
}

internal sealed class Unused : IServicesAdapter, INetworkAdapter, IAccountsAdapter
{
    public ServiceState Get(string name) => throw new NotSupportedException();
    public void SetStartType(string name, string startType, bool delayed = false) => throw new NotSupportedException();
    public void Start(string name) => throw new NotSupportedException();
    public void Stop(string name) => throw new NotSupportedException();
    public Profile? GetCategory(int index) => throw new NotSupportedException();
    public void SetCategory(int index, Profile profile) => throw new NotSupportedException();
    public AccountInfo? FindByRid(int rid) => throw new NotSupportedException();
    public void SetEnabled(string name, bool enabled) => throw new NotSupportedException();
}

public sealed class TempDir : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "simplysec-tests", Guid.NewGuid().ToString("N"));

    public TempDir() => Directory.CreateDirectory(Path);

    public string File(string name) => System.IO.Path.Combine(Path, name);

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, true);
        }
        catch (IOException)
        {
        }
    }
}

public static class TestEngines
{
    public static (ScanEngine Engine, Adapters Adapters) Make(TempDir tmp, bool admin = true, RawScan? raw = null)
    {
        var unused = new Unused();
        var adapters = new Adapters
        {
            Firewall = new FakeFirewall(),
            Registry = new FakeRegistry(),
            Services = unused,
            Network = unused,
            System = new FakeSystem(),
            Accounts = unused,
            Scheduler = new FakeScheduler(),
        };
        var engine = new ScanEngine(new EngineOptions
        {
            Adapters = () => adapters,
            Journal = ro => new Journal(tmp.File("data/simplysec.db"), ro),
            History = () => new History(tmp.File("user/history.db")),
            Collector = raw is null ? null : _ => raw,
            IsAdmin = () => admin,
            BackupsDir = tmp.File("backups"),
        });
        return (engine, adapters);
    }
}
