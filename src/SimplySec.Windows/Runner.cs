using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using Serilog;

namespace SimplySec.Windows;

public sealed class CommandException(string message, RunResult? result = null) : Exception(message)
{
    public RunResult? Result { get; } = result;
}

public sealed record RunResult(IReadOnlyList<string> Args, int Code, string Stdout, string Stderr)
{
    public bool Ok => Code == 0;
}

/// <summary>
/// Run external programs safely: no shell, no console window, timeouts, real exit codes.
/// PowerShell is only used to return objects as JSON; parameters travel as base64 JSON in an
/// environment variable, so nothing is spliced into script text.
/// </summary>
public static class Runner
{
    public static readonly string System32 = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "System32");
    public static readonly string PowerShellExe = Path.Combine(System32, "WindowsPowerShell", "v1.0", "powershell.exe");

    public static RunResult Run(IReadOnlyList<string> args, double timeout = 60, bool check = false, string? input = null,
        IDictionary<string, string>? env = null)
    {
        var psi = new ProcessStartInfo(args[0])
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = input is not null,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in args.Skip(1))
        {
            psi.ArgumentList.Add(a);
        }
        foreach (var (k, v) in env ?? new Dictionary<string, string>())
        {
            psi.Environment[k] = v;
        }
        var name = Path.GetFileName(args[0]);
        Process proc;
        try
        {
            proc = Process.Start(psi) ?? throw new CommandException($"could not start {args[0]}");
        }
        catch (System.ComponentModel.Win32Exception exc)
        {
            throw new CommandException($"could not start {args[0]}: {exc.Message}");
        }
        using (proc)
        {
            var stdout = proc.StandardOutput.ReadToEndAsync();
            var stderr = proc.StandardError.ReadToEndAsync();
            if (input is not null)
            {
                proc.StandardInput.Write(input);
                proc.StandardInput.Close();
            }
            if (!proc.WaitForExit(TimeSpan.FromSeconds(timeout)))
            {
                try
                {
                    proc.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException)
                {
                }
                throw new CommandException($"{name} timed out after {timeout:0}s");
            }
            proc.WaitForExit();
            var result = new RunResult(args, proc.ExitCode, stdout.Result, stderr.Result);
            if (!result.Ok)
            {
                Log.Information("{Name} exited with {Code}: {Err}", name, result.Code, Truncate(result.Stderr.Trim(), 500));
            }
            if (check && !result.Ok)
            {
                var detail = Truncate((result.Stderr.Length > 0 ? result.Stderr : result.Stdout).Trim(), 400);
                throw new CommandException($"{name} failed (exit {result.Code}): {detail}", result);
            }
            return result;
        }
    }

    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..n];

    private const string Prelude = """

        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'SilentlyContinue'
        [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
        $P = $null
        if ($env:SIMPLYSEC_PARAMS) {
          $P = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:SIMPLYSEC_PARAMS)) | ConvertFrom-Json
        }

        """;

    private static string[] PsArgs(params string[] tail) =>
        [PowerShellExe, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", .. tail];

    /// <summary>Run an inline PowerShell script; <c>$P</c> holds the parameters (decoded from JSON).</summary>
    public static RunResult PowerShell(string script, JsonNode? parameters = null, double timeout = 90)
    {
        var env = new Dictionary<string, string>();
        if (parameters is not null)
        {
            env["SIMPLYSEC_PARAMS"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(parameters.ToJsonString()));
        }
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(Prelude + script));
        try
        {
            var r = Run(PsArgs("-EncodedCommand", encoded), timeout, env: env);
            return r with { Args = ["powershell", "<script>"] };
        }
        catch (CommandException exc) when (exc.Message.Contains("timed out", StringComparison.Ordinal))
        {
            throw new CommandException($"PowerShell timed out after {timeout:0}s");
        }
    }

    /// <summary>Run PowerShell that writes one JSON document; failures raise, never pass silently.</summary>
    public static JsonNode? PowerShellJson(string script, JsonNode? parameters = null, double timeout = 90)
    {
        var res = PowerShell(script, parameters, timeout);
        if (!res.Ok)
        {
            throw new CommandException($"PowerShell failed (exit {res.Code}): {Truncate(res.Stderr.Trim(), 600)}", res);
        }
        var text = res.Stdout.Trim();
        if (text.Length == 0)
        {
            return null;
        }
        try
        {
            return JsonNode.Parse(text);
        }
        catch (System.Text.Json.JsonException)
        {
            throw new CommandException($"PowerShell returned invalid JSON: {Truncate(text, 200)}", res);
        }
    }

    /// <summary>Run a bundled .ps1 that prints JSON.</summary>
    public static JsonNode? PowerShellFile(string path, double timeout = 120)
    {
        var res = Run(PsArgs("-File", path), timeout);
        var name = Path.GetFileName(path);
        if (!res.Ok)
        {
            throw new CommandException($"{name} failed (exit {res.Code}): {Truncate(res.Stderr.Trim(), 600)}", res);
        }
        try
        {
            var text = res.Stdout.Trim();
            return JsonNode.Parse(text.Length > 0 ? text : "null");
        }
        catch (System.Text.Json.JsonException)
        {
            throw new CommandException($"{name} returned invalid JSON: {Truncate(res.Stdout, 200)}", res);
        }
    }
}
