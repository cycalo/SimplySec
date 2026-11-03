using System.Diagnostics;
using System.Text.Json.Nodes;
using Microsoft.Win32;
using Serilog;
using SimplySec.Core.Checks;
using SimplySec.Core.Compat;
using SimplySec.Core.Engine;
using SimplySec.Core.Eval;
using SimplySec.Core.Knowledge;
using SimplySec.Core.Model;

namespace SimplySec.Windows;

/// <summary>Collect everything a scan needs, in parallel. Read-only; works without admin.</summary>
public static class Collector
{
    /// <summary>Only these environment variables are kept; everything else may hold secrets.</summary>
    private static readonly HashSet<string> PathVars = new(StringComparer.Ordinal)
    {
        "SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432",
        "COMMONPROGRAMFILES", "COMMONPROGRAMFILES(X86)", "PROGRAMDATA", "ALLUSERSPROFILE",
        "LOCALAPPDATA", "APPDATA", "USERPROFILE", "PUBLIC", "TEMP", "TMP",
    };

    /// <summary>os.path.expandvars: $VAR, ${VAR} and %VAR% from the process environment.</summary>
    internal static string ExpandVars(string path)
    {
        if (!path.Contains('$') && !path.Contains('%'))
        {
            return path;
        }
        var env = System.Environment.GetEnvironmentVariables();
        string? Lookup(string name)
        {
            foreach (System.Collections.DictionaryEntry kv in env)
            {
                if (string.Equals((string)kv.Key, name, StringComparison.OrdinalIgnoreCase))
                {
                    return (string?)kv.Value;
                }
            }
            return null;
        }
        var sb = new System.Text.StringBuilder();
        var i = 0;
        while (i < path.Length)
        {
            var c = path[i];
            if (c == '\'' )
            {
                var end = path.IndexOf('\'', i + 1);
                if (end < 0)
                {
                    sb.Append(path[i..]);
                    break;
                }
                sb.Append(path, i, end - i + 1);
                i = end + 1;
            }
            else if (c == '%')
            {
                if (i + 1 < path.Length && path[i + 1] == '%')
                {
                    sb.Append('%');
                    i += 2;
                    continue;
                }
                var end = path.IndexOf('%', i + 1);
                if (end < 0)
                {
                    sb.Append(path[i..]);
                    break;
                }
                var name = path[(i + 1)..end];
                sb.Append(Lookup(name) ?? path[i..(end + 1)]);
                i = end + 1;
            }
            else if (c == '$')
            {
                if (i + 1 < path.Length && path[i + 1] == '$')
                {
                    sb.Append('$');
                    i += 2;
                }
                else if (i + 1 < path.Length && path[i + 1] == '{')
                {
                    var end = path.IndexOf('}', i + 2);
                    if (end < 0)
                    {
                        sb.Append(path[i..]);
                        break;
                    }
                    var name = path[(i + 2)..end];
                    sb.Append(Lookup(name) ?? path[i..(end + 1)]);
                    i = end + 1;
                }
                else
                {
                    var j = i + 1;
                    while (j < path.Length && (char.IsAsciiLetterOrDigit(path[j]) || path[j] is '_' or '-'))
                    {
                        j++;
                    }
                    var name = path[(i + 1)..j];
                    sb.Append(name.Length > 0 ? Lookup(name) ?? path[i..j] : "$");
                    i = name.Length > 0 ? j : i + 1;
                }
            }
            else
            {
                sb.Append(c);
                i++;
            }
        }
        return sb.ToString();
    }

    /// <summary>Process env plus the user's and machine's stored variables, filtered to safe keys.</summary>
    public static OrderedDictionary<string, string> SafeEnvironment()
    {
        var wanted = new HashSet<string>(PathVars, StringComparer.Ordinal);
        foreach (var p in KnowledgeBase.Get().Programs.Where(p => p.IntentEnv.Length > 0))
        {
            wanted.Add(PyStr.Upper(p.IntentEnv));
        }
        var env = new OrderedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var (hive, sub) in new[] { (RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"), (RegistryHive.CurrentUser, "Environment") })
        {
            try
            {
                using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
                using var key = root.OpenSubKey(sub);
                if (key is null)
                {
                    continue;
                }
                foreach (var name in key.GetValueNames())
                {
                    if (wanted.Contains(PyStr.Upper(name)) && key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string value)
                    {
                        env[PyStr.Upper(name)] = ExpandVars(value);
                    }
                }
            }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
            }
        }
        foreach (System.Collections.DictionaryEntry kv in System.Environment.GetEnvironmentVariables())
        {
            var k = PyStr.Upper((string)kv.Key);
            if (wanted.Contains(k))
            {
                env[k] = (string?)kv.Value ?? "";
            }
        }
        return env;
    }

    private static JsonObject Facts()
    {
        var data = Runner.PowerShellFile(Paths.FactsScript, timeout: 180);
        return data as JsonObject ?? [];
    }

    public static RawScan Collect(Action<string>? progress = null)
    {
        var sw = Stopwatch.StartNew();
        var stamp = PyTime.NowIsoSeconds();
        var errors = new List<string>();
        void Say(string text) => progress?.Invoke(text);

        Say("Reading listening programs, firewall rules and Windows security settings…");
        var tFacts = Task.Run(Facts);
        var tListeners = Task.Run(Listeners.ReadListeners);
        var tFirewall = Task.Run(() => Firewall.ReadState());

        List<Listener> lst;
        try
        {
            lst = tListeners.GetAwaiter().GetResult();
            Say(Progress.MarkDone($"Found {lst.Count} listening sockets"));
        }
        catch (Exception exc)
        {
            Log.Error(exc, "listeners failed");
            errors.Add($"could not list listening ports: {exc.Message}");
            lst = [];
            Say(Progress.MarkDone("Could not list listening programs (reported as a problem)"));
        }
        FirewallState fw;
        try
        {
            fw = tFirewall.GetAwaiter().GetResult();
            Say(Progress.MarkDone($"Read {fw.Rules.Count} firewall rules"));
        }
        catch (Exception exc)
        {
            Log.Error(exc, "firewall read failed");
            errors.Add($"could not read the firewall: {exc.Message}");
            fw = new FirewallState();
            Say(Progress.MarkDone("Could not read the firewall (reported as a problem)"));
        }

        var env = SafeEnvironment();
        var windowsDir = env.TryGetValue("SYSTEMROOT", out var sr) ? sr : @"C:\Windows";
        var exes = new HashSet<string>(lst.Where(x => x.Exe.Length > 0).Select(x => x.Exe), StringComparer.Ordinal);
        foreach (var r in fw.Rules)
        {
            if (r.Enabled && r.Direction == "in" && r.Action == "allow" && (r.ProfileMask & (int)Profile.Public) != 0)
            {
                var app = Evaluator.NormalizeAppPath(r.Application, env);
                if (app.Length > 0 && app != "system" && !app.StartsWith(PyStr.Lower(windowsDir), StringComparison.Ordinal))
                {
                    exes.Add(app);
                }
            }
        }
        Say($"Checking {exes.Count} program signatures and saved Wi-Fi networks…");
        var tSigs = Task.Run(() => Listeners.Signatures(exes.Order(StringComparer.Ordinal)));
        var tWifi = Task.Run(Wifi.Fact);
        var tUsage = Task.Run(() => Usage.Collect(lst));

        var facts = new JsonObject();
        var sigs = new OrderedDictionary<string, SignatureInfo>(StringComparer.Ordinal);
        JsonObject wifiFact = new() { ["status"] = "error", ["error"] = "not collected" };
        JsonObject usageFact = new() { ["status"] = "error", ["error"] = "not collected" };
        var labels = new Dictionary<Task, string>
        {
            [tFacts] = "Windows security settings (Defender, updates, sharing, accounts…)",
            [tSigs] = "program signatures",
            [tWifi] = "saved Wi-Fi networks",
            [tUsage] = "what's in use right now (connections, sessions, drives)",
        };
        var pending = labels.Keys.ToList();
        while (pending.Count > 0)
        {
            var done = Task.WhenAny(pending).GetAwaiter().GetResult();
            pending.Remove(done);
            try
            {
                if (done == tFacts)
                {
                    facts = tFacts.GetAwaiter().GetResult();
                    Say(Progress.MarkDone($"Read {labels[done]}"));
                }
                else if (done == tSigs)
                {
                    foreach (var (k, v) in tSigs.GetAwaiter().GetResult())
                    {
                        sigs[k] = new SignatureInfo(v.Status, Listeners.Publisher(v.Signer));
                    }
                    Say(Progress.MarkDone($"Checked {sigs.Count} {labels[done]}"));
                }
                else if (done == tUsage)
                {
                    usageFact = tUsage.GetAwaiter().GetResult();
                    var n = (usageFact["value"]?["connections"] as JsonArray)?.Count ?? 0;
                    Say(Progress.MarkDone($"Checked what's in use right now ({n} incoming connection(s))"));
                }
                else
                {
                    wifiFact = tWifi.GetAwaiter().GetResult();
                    Say(Progress.MarkDone($"Read {labels[done]}"));
                }
            }
            catch (Exception exc)
            {
                Log.Warning("{What} failed: {Error}", labels[done], exc.Message);
                errors.Add($"could not read {labels[done]}: {exc.Message}");
                Say(Progress.MarkDone($"Could not read {labels[done]} (reported as a problem)"));
            }
            if (pending.Count > 0)
            {
                Say("Still waiting for: " + string.Join(", ", pending.Select(p => labels[p])) + "…");
            }
        }
        facts["wifi"] = wifiFact;
        facts["usage"] = usageFact;

        var netFact = facts["network"] is JsonObject n2 ? n2["value"] : null;
        List<NetInterface> interfaces;
        try
        {
            interfaces = Network.BuildInterfaces(netFact);
        }
        catch (Exception exc)
        {
            Log.Error(exc, "interfaces failed");
            errors.Add($"could not read network adapters: {exc.Message}");
            interfaces = [];
        }
        return new RawScan
        {
            Facts = facts,
            Listeners = lst,
            Firewall = fw,
            Interfaces = interfaces,
            Signatures = sigs,
            Env = env,
            IsAdmin = Elevation.IsAdmin(),
            WindowsDir = windowsDir,
            Errors = errors,
            Started = stamp,
            Duration = sw.Elapsed.TotalSeconds,
        };
    }
}
