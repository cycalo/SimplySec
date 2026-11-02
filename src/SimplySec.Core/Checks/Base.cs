using System.Security.Cryptography;
using System.Text.Json.Nodes;
using SimplySec.Core.Compat;
using SimplySec.Core.Knowledge;
using SimplySec.Core.Model;

namespace SimplySec.Core.Checks;

/// <summary>
/// Process-wide sources of nondeterminism. Tests pin them so results can be compared with the
/// Python v2 golden data; production uses the real clock and random rule ids.
/// </summary>
public static class Ambient
{
    public static TimeProvider Clock { get; set; } = TimeProvider.System;

    /// <summary>The random part of new firewall rule names (secrets.token_hex(4) in v2).</summary>
    public static Func<string> RuleToken { get; set; } = () => Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant();

    public static DateTimeOffset UtcNow => Clock.GetUtcNow();

    public static DateTimeOffset LocalNow => Clock.GetLocalNow();
}

/// <summary>facts.ps1 output with explicit status per item (ok / needs_admin / error / missing).</summary>
public sealed class Facts(JsonObject? data)
{
    public JsonObject Data { get; } = data ?? [];

    public string Status(string name)
    {
        var item = Data.TryGetPropertyValue(name, out var v) ? v : null;
        if (item is not JsonObject o)
        {
            return "missing";
        }
        return o.TryGetPropertyValue("status", out var s) ? Js.PyRepr(s) : "missing";
    }

    public JsonNode? Get(string name)
    {
        var item = Data.TryGetPropertyValue(name, out var v) ? v : null;
        if (item is JsonObject o && o.TryGetPropertyValue("status", out var s) && Js.IsString(s) && s!.GetValue<string>() == "ok")
        {
            return o.TryGetPropertyValue("value", out var value) ? value : null;
        }
        return null;
    }

    /// <summary>Like Get, but Python's <c>x or {}</c>: a falsy value becomes an empty object.</summary>
    public JsonNode GetOrEmpty(string name)
    {
        var v = Get(name);
        return Js.Truthy(v) ? v! : new JsonObject();
    }

    public string Error(string name)
    {
        var item = Data.TryGetPropertyValue(name, out var v) ? v : null;
        return item is JsonObject o ? (o.TryGetPropertyValue("error", out var e) ? Js.PyRepr(e) : "") : "";
    }
}

public sealed record SignatureInfo(string Status, string Publisher = "")
{
    public bool Signed => Status == "Valid";
}

/// <summary>All listeners of one program on one protocol/port, with the combined exposure.</summary>
public sealed class PortGroup
{
    public required string Protocol { get; init; }
    public required int Port { get; init; }
    public required int Pid { get; init; }
    public string Process { get; init; } = "";
    public string Exe { get; init; } = "";
    public List<string>? Services { get; init; }
    public List<Exposure> Exposures { get; } = [];

    public List<Listener> Listeners => Exposures.Select(e => e.Listener).ToList();
    public List<string> Addresses => Exposures.Select(e => e.Listener.Address).ToList();
}

public sealed class ScanContext
{
    public required Facts Facts { get; init; }
    public required List<Listener> Listeners { get; init; }
    public required List<Exposure> Exposures { get; init; }
    public required List<PortGroup> Groups { get; init; }
    public required List<NetInterface> Interfaces { get; init; }
    public required FirewallState Firewall { get; init; }
    public required KnowledgeBase Kb { get; init; }
    public Dictionary<string, SignatureInfo> Signatures { get; init; } = new(StringComparer.Ordinal);
    public bool IsAdmin { get; init; }
    public Dictionary<string, string> Env { get; init; } = new(StringComparer.Ordinal);
    public Dictionary<string, int> Accepted { get; init; } = new(StringComparer.Ordinal);
    public string WindowsDir { get; init; } = @"C:\Windows";
    public Func<string, bool> FileExists { get; init; } = _ => true;

    /// <summary>A FixOption for any registered fix, with parameters derived from this scan.</summary>
    public FixOption? FixOption(string fixId, JsonObject? parameters = null)
    {
        if (!Registry.Fixes.TryGetValue(fixId, out var fix))
        {
            return null;
        }
        if (parameters is null && fix.ParamsFrom is not null)
        {
            parameters = fix.ParamsFrom(this);
            if (parameters is null)
            {
                return null;
            }
        }
        return fix.Option(parameters);
    }

    public bool Managed
    {
        get
        {
            var system = Facts.GetOrEmpty("system");
            return Js.Truthy(Js.Get(system, "part_of_domain")) || Firewall.ManagedByPolicy;
        }
    }

    public List<NetInterface> ActiveInterfaces() =>
        Interfaces.Where(i => i.Up && i.Kind != InterfaceKind.Loopback && i.IpInterfaces().Count > 0).ToList();

    /// <summary>Physical networks (Ethernet / Wi-Fi) Windows currently treats as Public.</summary>
    public List<NetInterface> CurrentPublicNetworks() =>
        ActiveInterfaces().Where(i => i.Kind is InterfaceKind.Ethernet or InterfaceKind.Wifi && i.Profile == Profile.Public).ToList();

    public SignatureInfo? Signature(string? exe) =>
        Signatures.TryGetValue(PyStr.Lower(exe), out var s) ? s : null;

    public bool IsWindowsBinary(string? exe) =>
        !string.IsNullOrEmpty(exe) && PyStr.Lower(exe).StartsWith(PyStr.Lower(WindowsDir).TrimEnd('\\') + "\\", StringComparison.Ordinal);
}

// --------------------------------------------------------------------------- fixes

public sealed class FixWarning
{
    public string Text { get; init; } = "";
    public string? OfferFix { get; init; }
    public JsonObject OfferParams { get; init; } = [];
    public string OfferLabel { get; init; } = "";

    public JsonObject ToJson() => new()
    {
        ["text"] = Text,
        ["offer_fix"] = OfferFix,
        ["offer_params"] = Js.CloneObj(OfferParams),
        ["offer_label"] = OfferLabel,
    };
}

public sealed class FixDef
{
    public required string Id { get; init; }
    public required string Label { get; init; }
    public required string Description { get; init; }
    public required string MightBreak { get; init; }
    public Func<JsonObject, List<ActionSpec>>? Build { get; init; }
    public bool Disruptive { get; init; }
    public bool Recommended { get; init; }
    /// <summary>Settings page to open instead of changing anything.</summary>
    public string? Guidance { get; init; }
    public Func<ScanContext, JsonObject, List<FixWarning>>? Warnings { get; init; }
    public Func<ScanContext, JsonObject?>? ParamsFrom { get; init; }

    public FixOption Option(JsonObject? parameters = null, string? label = null) => new()
    {
        FixId = Id,
        Label = string.IsNullOrEmpty(label) ? Label : label,
        Params = parameters ?? [],
        Disruptive = Disruptive,
        Recommended = Recommended,
        GuidanceOnly = Guidance is not null,
    };
}

public sealed record Allow(string Kind, Func<JsonObject, bool> Predicate);

public sealed class Check
{
    public required string Id { get; init; }
    public required string Area { get; init; }
    public required Func<ScanContext, List<Finding>> Run { get; init; }
    public List<FixDef> Fixes { get; init; } = [];
    public List<Allow> Allows { get; init; } = [];
}

// --------------------------------------------------------------------------- helpers

public static class CheckHelpers
{
    /// <summary>Allow registry.value changes to exactly these (path, name) pairs.</summary>
    public static Allow RegAllow(params (string Path, string Name)[] pairs)
    {
        var allowed = pairs.Select(p => (PyStr.Lower(p.Path), PyStr.Lower(p.Name))).ToHashSet();
        return new Allow("registry.value", p =>
            allowed.Contains((PyStr.Lower(Js.PyRepr(Js.Get(p, "path") ?? JsonValue.Create(""))), PyStr.Lower(Js.PyRepr(Js.Get(p, "name") ?? JsonValue.Create(""))))));
    }

    public static ActionSpec RegAction(string path, string name, long value, string vtype, string summary) =>
        new("registry.value", new JsonObject { ["path"] = path, ["name"] = name, ["value"] = value, ["type"] = vtype }, summary);

    public static Finding NewFinding(
        string id, string check, string area, string title, Severity severity, string what,
        List<(string, string)>? details = null, List<FixOption>? fixes = null, string learnMore = "") => new()
    {
        Id = id,
        Check = check,
        Area = area,
        Title = title,
        Severity = severity,
        WhatItMeans = what,
        Details = details ?? [],
        Fixes = fixes ?? [],
        LearnMore = learnMore,
    };

    /// <summary>An Info finding when a fact could not be read, so 'unknown' never looks like 'safe'.</summary>
    public static Finding? FactUnavailable(ScanContext ctx, string name, string check, string area, string what)
    {
        var status = ctx.Facts.Status(name);
        if (status == "ok")
        {
            return null;
        }
        var reason = status switch
        {
            "needs_admin" => "SimplySec needs administrator rights to read this.",
            "missing" => "This information was not collected.",
            _ => $"Windows reported an error: {Truncate(ctx.Facts.Error(name), 200)}",
        };
        return NewFinding($"{check}.unavailable.{name}", check, area, $"Could not check {what}", Severity.Info,
            $"{reason} This is reported as unknown, not as safe.");
    }

    public static string Truncate(string s, int n) => s.Length <= n ? s : s[..n];

    /// <summary>Python <c>str(value)</c> of an optional JSON value.</summary>
    public static string S(JsonNode? n) => Js.PyRepr(n);

    /// <summary>Python <c>d.get(key, default)</c>: the default only when the key is missing.</summary>
    public static JsonNode? GetOr(JsonNode? d, string key, JsonNode? def) =>
        d is JsonObject o && o.TryGetPropertyValue(key, out var v) ? v : def;

    public static string GetStr(JsonNode? d, string key, string def = "") =>
        d is JsonObject o && o.TryGetPropertyValue(key, out var v) ? Js.PyRepr(v) : def;
}
