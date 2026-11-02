using System.Reflection;
using SimplySec.Core.Compat;
using SimplySec.Core.Model;
using Tomlyn;
using Tomlyn.Model;

namespace SimplySec.Core.Knowledge;

public interface IPortOrRange
{
    string Name { get; }
    Severity Risk { get; }
    string Summary { get; }
    string Explain { get; }
    string Advice { get; }
}

public sealed record PortInfo(
    int Port, string Protocol, string Name, Severity Risk, string Summary, string Explain, string Advice,
    string Topic = "", bool Kernel = false, string Service = "", bool LanProbe = false,
    IReadOnlyList<string>? Fixes = null, bool Discovery = false) : IPortOrRange
{
    public IReadOnlyList<string> FixIds => Fixes ?? [];
}

public sealed record RangeInfo(
    int Start, int End, string Protocol, string Name, Severity Risk, string Summary, string Explain, string Advice) : IPortOrRange;

public sealed record ProgramInfo(
    string Id, IReadOnlyList<string> Exe, string Name, string Description, Severity Risk, string Explain,
    string IntentEnv = "", IReadOnlyList<long>? Ports = null);

public sealed record ServiceInfo(string Name, string Display, string Description, Severity Risk, bool NeverTouch = false);

/// <summary>The knowledge base: ports, programs and services (the single source of truth).</summary>
public sealed class KnowledgeBase
{
    public OrderedDictionary<(string Protocol, int Port), PortInfo> Ports { get; } = [];
    public List<RangeInfo> Ranges { get; } = [];
    public List<ProgramInfo> Programs { get; } = [];
    public OrderedDictionary<string, ServiceInfo> Services { get; } = new(StringComparer.Ordinal);
    public List<string> Errors { get; } = [];

    private static readonly Lazy<KnowledgeBase> Default = new(() => Load());

    public static KnowledgeBase Get() => Default.Value;

    public PortInfo? Port(string protocol, int port) =>
        Ports.TryGetValue((PyStr.Lower(protocol), port), out var p) ? p : null;

    public IPortOrRange? PortOrRange(string protocol, int port)
    {
        var exact = Port(protocol, port);
        if (exact is not null)
        {
            return exact;
        }
        return Ranges.FirstOrDefault(r => r.Protocol == protocol && r.Start <= port && port <= r.End);
    }

    public ProgramInfo? Program(string? exeOrName)
    {
        var name = PyStr.Lower(NtPath.Basename(exeOrName ?? ""));
        if (name.Length == 0)
        {
            return null;
        }
        return Programs.FirstOrDefault(p => p.Exe.Contains(name));
    }

    public ProgramInfo? ProgramById(string id) => Programs.FirstOrDefault(p => p.Id == id);

    public ServiceInfo? Service(string? name) =>
        Services.TryGetValue(PyStr.Lower(name), out var s) ? s : null;

    public HashSet<string> NeverTouch =>
        Services.Values.Where(s => s.NeverTouch).Select(s => PyStr.Lower(s.Name)).ToHashSet(StringComparer.Ordinal);

    public List<PortInfo> LanProbePorts() =>
        Ports.Values.Where(p => p.LanProbe && p.Protocol == "tcp").OrderBy(p => p.Port).ToList();

    public HashSet<string> AllFixIds() =>
        Ports.Values.SelectMany(p => p.FixIds).ToHashSet(StringComparer.Ordinal);

    // ------------------------------------------------------------------ loading

    private static Severity Risk(object? value, string where, List<string> errors)
    {
        try
        {
            return value switch
            {
                long l => (Severity)l,
                string s => EnumText.ParseSeverity(s),
                _ => throw new KeyNotFoundException(),
            };
        }
        catch (KeyNotFoundException)
        {
            errors.Add($"{where}: unknown risk '{value}'");
            return Severity.Medium;
        }
    }

    private static string ReadResource(string name)
    {
        var asm = typeof(KnowledgeBase).Assembly;
        using var stream = asm.GetManifestResourceStream(name) ?? throw new FileNotFoundException(name);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    public static KnowledgeBase Load(string? directory = null)
    {
        string Text(string file) => directory is null
            ? ReadResource("knowledge/" + file)
            : File.ReadAllText(Path.Combine(directory, file));

        var kb = new KnowledgeBase();
        var errors = kb.Errors;

        var data = Toml.ToModel(Text("ports.toml"));
        foreach (var entry in Tables(data, "port"))
        {
            var where = $"ports.toml {Py(Get(entry, "protocol"))}/{Py(Get(entry, "port"))}";
            var proto = PyStr.Lower(Py(Get(entry, "protocol"), ""));
            if (proto is not ("tcp" or "udp"))
            {
                errors.Add($"{where}: protocol must be tcp or udp");
                continue;
            }
            foreach (var req in new[] { "name", "summary", "explain", "advice", "risk" })
            {
                if (!Truthy(Get(entry, req)))
                {
                    errors.Add($"{where}: missing {req}");
                }
            }
            var key = (proto, (int)(long)entry["port"]);
            if (kb.Ports.ContainsKey(key))
            {
                errors.Add($"{where}: duplicate entry");
                continue;
            }
            kb.Ports[key] = new PortInfo(
                key.Item2, proto, Str(entry, "name"),
                Risk(Get(entry, "risk") ?? "medium", where, errors),
                Str(entry, "summary"), Str(entry, "explain"), Str(entry, "advice"),
                Str(entry, "topic"), Bool(entry, "kernel"), Str(entry, "service"), Bool(entry, "lan_probe"),
                StrList(entry, "fixes"), Bool(entry, "discovery"));
        }
        foreach (var entry in Tables(data, "range"))
        {
            var where = $"ports.toml range {Py(Get(entry, "start"))}-{Py(Get(entry, "end"))}";
            kb.Ranges.Add(new RangeInfo(
                (int)(long)entry["start"], (int)(long)entry["end"], (string)entry["protocol"], (string)entry["name"],
                Risk(entry["risk"], where, errors), (string)entry["summary"], (string)entry["explain"], (string)entry["advice"]));
        }

        data = Toml.ToModel(Text("programs.toml"));
        var seenIds = new HashSet<string>(StringComparer.Ordinal);
        var seenExe = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var entry in Tables(data, "program"))
        {
            var pid = Str(entry, "id");
            var where = $"programs.toml {pid}";
            if (!seenIds.Add(pid))
            {
                errors.Add($"{where}: duplicate id");
            }
            var exes = StrList(entry, "exe").Select(PyStr.Lower).ToList();
            foreach (var e in exes)
            {
                if (seenExe.TryGetValue(e, out var other))
                {
                    errors.Add($"{where}: exe {e} already listed under {other}");
                }
                seenExe[e] = pid;
            }
            kb.Programs.Add(new ProgramInfo(
                pid, exes, Str(entry, "name", pid), Str(entry, "description", pid),
                Risk(Get(entry, "risk") ?? "medium", where, errors), Str(entry, "explain"), Str(entry, "intent_env"),
                (Get(entry, "ports") as TomlArray)?.Select(x => Convert.ToInt64(x, System.Globalization.CultureInfo.InvariantCulture)).ToList() ?? []));
        }

        data = Toml.ToModel(Text("services.toml"));
        foreach (var entry in Tables(data, "service"))
        {
            var name = Str(entry, "name");
            var where = $"services.toml {name}";
            if (kb.Services.ContainsKey(PyStr.Lower(name)))
            {
                errors.Add($"{where}: duplicate entry");
            }
            kb.Services[PyStr.Lower(name)] = new ServiceInfo(
                name, Str(entry, "display", name), Str(entry, "description"),
                Risk(Get(entry, "risk") ?? "low", where, errors), Bool(entry, "never_touch"));
        }
        return kb;
    }

    private static IEnumerable<TomlTable> Tables(TomlTable data, string key) =>
        data.TryGetValue(key, out var v) && v is TomlTableArray arr ? arr : [];

    private static object? Get(TomlTable t, string key) => t.TryGetValue(key, out var v) ? v : null;

    private static string Str(TomlTable t, string key, string def = "") => Get(t, key) as string ?? def;

    private static bool Bool(TomlTable t, string key) => Get(t, key) is bool b && b;

    private static List<string> StrList(TomlTable t, string key) =>
        (Get(t, key) as TomlArray)?.Select(x => x?.ToString() ?? "").ToList() ?? [];

    private static bool Truthy(object? v) => v switch
    {
        null => false,
        string s => s.Length > 0,
        long l => l != 0,
        bool b => b,
        _ => true,
    };

    private static string Py(object? v, string none = "None") => v switch
    {
        null => none,
        long l => l.ToString(System.Globalization.CultureInfo.InvariantCulture),
        _ => v.ToString() ?? none,
    };
}
