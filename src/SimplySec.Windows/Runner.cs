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
/// </summary>
public static class Runner
{
    public static readonly string System32 = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "System32");

    /// <summary>Raised with the file name of every program started (a test checks a scan starts no PowerShell).</summary>
    public static event Action<string>? Started;

    /// <summary>Run a program. In <paramref name="env"/>, a null value removes that variable.</summary>
    public static RunResult Run(IReadOnlyList<string> args, double timeout = 60, bool check = false, string? input = null,
        IDictionary<string, string?>? env = null)
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
        foreach (var (k, v) in env ?? new Dictionary<string, string?>())
        {
            if (v is null)
            {
                psi.Environment.Remove(k);
            }
            else
            {
                psi.Environment[k] = v;
            }
        }
        var name = Path.GetFileName(args[0]);
        Log.Debug("running {Name}", name);
        Started?.Invoke(name);
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
}
