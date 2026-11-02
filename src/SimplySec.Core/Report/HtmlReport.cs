using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using SimplySec.Core.Checks;
using SimplySec.Core.Compat;
using SimplySec.Core.Engine;
using SimplySec.Core.Model;

namespace SimplySec.Core.Report;

/// <summary>
/// Self-contained, printable HTML report. Every value is HTML-encoded: device names, router names
/// and port-forward descriptions come from the network and are untrusted.
/// </summary>
public static class HtmlReport
{
    /// <summary>Five small-business control areas (the Cyber Essentials themes), mapped from finding areas.</summary>
    public static readonly (string Name, string Blurb, string[] Areas)[] ControlAreas =
    [
        ("Firewalls", "Which services other devices and the internet can reach.", ["Firewall", "Exposure", "Router"]),
        ("Secure configuration", "Settings that remove unnecessary ways in.",
            ["Remote access", "Legacy protocols", "File sharing", "System", "Wi-Fi", "Home network", "Housekeeping"]),
        ("User access control", "Who can sign in and with which rights.", ["Accounts"]),
        ("Malware protection", "Antivirus and ransomware protection.", ["Malware protection"]),
        ("Security update management", "Keeping Windows patched.", ["Updates"]),
    ];

    public static string ControlArea(string area) =>
        ControlAreas.FirstOrDefault(c => c.Areas.Contains(area)).Name ?? "Secure configuration";

    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

    private static string E(JsonNode? n) => E(Js.IsNull(n) ? "" : Js.PyRepr(n));

    private static string When(string? iso) => (iso ?? "").Length > 16 ? iso![..16].Replace('T', ' ') : (iso ?? "").Replace('T', ' ');

    private const string Style = """
          :root { --text:#1b1b1b; --dim:#5d5d5d; --line:#e5e5e5; --card:#fff; --bg:#f6f6f6; --accent:#0067c0;
                  --critical:#c42b1c; --high:#d83b01; --medium:#b76e00; --low:#0f6cbd; --info:#6b6b6b; --good:#0f7b0f; }
          * { box-sizing: border-box; }
          body { font: 14px/1.5 "Segoe UI", system-ui, sans-serif; color: var(--text); background: var(--bg); margin: 0; }
          main { max-width: 980px; margin: 0 auto; padding: 24px 16px 48px; }
          h1 { font-size: 26px; margin: 0 0 4px; } h2 { font-size: 19px; margin: 28px 0 8px; } h3 { font-size: 15px; margin: 0; }
          .dim { color: var(--dim); }
          .card { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 14px 16px; margin: 10px 0; }
          .summary { display: flex; gap: 24px; align-items: center; flex-wrap: wrap; }
          .grade { font-size: 44px; font-weight: 700; width: 92px; height: 92px; border-radius: 50%; display: flex;
                   align-items: center; justify-content: center; border: 8px solid var(--accent); }
          .counts span { display: inline-block; margin-right: 14px; font-weight: 600; }
          .chip { display: inline-block; border-radius: 4px; padding: 0 6px; color: #fff; font-size: 12px; font-weight: 600; }
          .critical { background: var(--critical); } .high { background: var(--high); } .medium { background: var(--medium); }
          .low { background: var(--low); } .info { background: var(--info); }
          .status { font-weight: 600; } .status.Good { color: var(--good); } .status.Could { color: var(--medium); } .status.Needs { color: var(--critical); }
          table { border-collapse: collapse; width: 100%; font-size: 13px; }
          th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
          th { background: #fafafa; }
          details summary { cursor: pointer; color: var(--accent); }
          .finding { border-top: 1px solid var(--line); padding: 10px 0; } .finding:first-of-type { border-top: none; }
          .tag { font-size: 12px; color: var(--dim); border: 1px solid var(--line); border-radius: 4px; padding: 0 5px; margin-left: 6px; }
          svg { max-width: 100%; }
          @media print { body { background: #fff; } .card { break-inside: avoid; } details { display: block; } details summary { display: none; } }
        """;

    public static string Render(ScanResult result, List<JsonObject>? changes = null, List<JsonObject>? accepted = null,
        List<(string Date, int Score)>? trend = null, string? generated = null)
    {
        changes ??= [];
        accepted ??= [];
        trend ??= [];
        generated ??= Ambient.LocalNow.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
        var counts = result.Counts();
        var h = new StringBuilder();
        h.Append("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
         .Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
         .Append(CultureInfo.InvariantCulture, $"<title>SimplySec report – {E(result.Computer)}</title>\n<style>\n{Style}</style>\n</head>\n<body>\n<main>\n");
        h.Append(CultureInfo.InvariantCulture, $"  <h1>Security report for {E(result.Computer)}</h1>\n");
        h.Append(CultureInfo.InvariantCulture, $"  <div class=\"dim\">SimplySec {E(AppInfo.Version)} · scan {E(When(result.Started))} · generated {E(generated)}{(result.IsAdmin ? "" : " · read-only scan")}</div>\n");

        h.Append("  <div class=\"card summary\">\n");
        h.Append(CultureInfo.InvariantCulture, $"    <div class=\"grade\">{E(result.Grade)}</div>\n    <div>\n");
        h.Append(CultureInfo.InvariantCulture, $"      <div style=\"font-size:20px; font-weight:600\">Risk score {result.Score}/100 <span class=\"dim\" style=\"font-size:13px; font-weight:400\">(lower is better)</span></div>\n");
        h.Append("      <div class=\"counts\">\n");
        h.Append(CultureInfo.InvariantCulture, $"        <span style=\"color:var(--critical)\">{E(counts["critical"])} critical</span>\n");
        h.Append(CultureInfo.InvariantCulture, $"        <span style=\"color:var(--high)\">{E(counts["high"])} high</span>\n");
        h.Append(CultureInfo.InvariantCulture, $"        <span style=\"color:var(--medium)\">{E(counts["medium"])} medium</span>\n");
        h.Append(CultureInfo.InvariantCulture, $"        <span style=\"color:var(--low)\">{E(counts["low"])} low</span>\n      </div>\n");
        foreach (var line in result.NetworkStatus())
        {
            h.Append(CultureInfo.InvariantCulture, $"      <div class=\"dim\">{E(line)}</div>");
        }
        h.Append("\n    </div>\n");
        if (trend.Count > 1)
        {
            const int w = 260, ht = 70;
            var n = trend.Count;
            var points = string.Concat(trend.Select((t, i) => string.Create(CultureInfo.InvariantCulture,
                $"{Math.Round(i * (w - 10) / (double)(n - 1) + 5, 1):0.0},{Math.Round(ht - 5 - t.Score * (ht - 10) / 100.0, 1):0.0} ")));
            h.Append(CultureInfo.InvariantCulture, $"    <div>\n      <div class=\"dim\">Risk score over time</div>\n      <svg width=\"{w}\" height=\"{ht}\" viewBox=\"0 0 {w} {ht}\" role=\"img\" aria-label=\"Risk score trend\">\n");
            h.Append(CultureInfo.InvariantCulture, $"        <polyline fill=\"none\" stroke=\"#0067c0\" stroke-width=\"2\"\n          points=\"{points}\"/>\n      </svg>\n    </div>\n");
        }
        h.Append("  </div>\n\n  <h2>Findings by control area</h2>\n");

        foreach (var (name, blurb, _) in ControlAreas)
        {
            var items = result.Findings.Where(f => ControlArea(f.Area) == name).ToList();
            var open = items.Where(f => f.Status == FindingStatus.Open && f.Severity > Severity.Info).ToList();
            var worst = open.Count > 0 ? open.Max(f => f.Severity) : (Severity?)null;
            var status = worst is >= Severity.High ? "Needs attention" : open.Count > 0 ? "Could be better" : "Good";
            h.Append(CultureInfo.InvariantCulture, $"  <div class=\"card\">\n    <h3>{E(name)} <span class=\"status {E(status.Split(' ')[0])}\">– {E(status)}</span></h3>\n");
            h.Append(CultureInfo.InvariantCulture, $"    <div class=\"dim\">{E(blurb)}</div>\n");
            if (items.Count == 0)
            {
                h.Append("    <p class=\"dim\">No findings.</p>\n");
            }
            foreach (var f in items)
            {
                h.Append(CultureInfo.InvariantCulture, $"    <div class=\"finding\">\n      <span class=\"chip {f.Severity.Key()}\">{E(f.Severity.Label())}</span>\n      <strong>{E(f.Title)}</strong>\n");
                if (f.Status != FindingStatus.Open)
                {
                    var tag = f.Status switch
                    {
                        FindingStatus.Accepted => "Kept",
                        FindingStatus.Managed => "Managed by organisation",
                        _ => "For information",
                    };
                    h.Append(CultureInfo.InvariantCulture, $"      <span class=\"tag\">{E(tag)}</span>\n");
                }
                h.Append(CultureInfo.InvariantCulture, $"      <div>{E(f.WhatItMeans)}</div>\n");
                if (f.Fixes.Count > 0)
                {
                    h.Append(CultureInfo.InvariantCulture, $"      <div class=\"dim\">Suggested: {E(string.Join("; ", f.Fixes.Select(x => x.Label)))}</div>\n");
                }
                if (f.Details.Count > 0)
                {
                    h.Append("      <details><summary>Technical details</summary>\n        <table>");
                    foreach (var (k, v) in f.Details)
                    {
                        h.Append(CultureInfo.InvariantCulture, $"<tr><th>{E(k)}</th><td>{E(v)}</td></tr>");
                    }
                    h.Append("</table>\n      </details>\n");
                }
                h.Append("    </div>\n");
            }
            h.Append("  </div>\n");
        }

        h.Append("\n  <h2>Ports other devices can reach</h2>\n  <div class=\"card\">\n");
        var ports = result.Ports.Where(p => p.Verdict is Verdict.Reachable or Verdict.Uncertain).ToList();
        if (ports.Count > 0)
        {
            h.Append("    <table>\n      <tr><th>Port</th><th>Program</th><th>Listening on</th><th>Reachable from</th><th>Risk</th></tr>\n");
            foreach (var p in ports)
            {
                var pub = p.Publisher.Length > 0 ? $" <span class=\"dim\">({E(p.Publisher)})</span>" : "";
                var risk = p.Verdict == Verdict.Reachable ? p.Risk.Label() : "Uncertain";
                h.Append(CultureInfo.InvariantCulture, $"      <tr><td>{E(PyStr.Upper(p.Protocol))} {p.Port}</td><td>{E(p.Process)}{pub}</td><td>{E(p.ListeningOn)}</td><td>{E(p.ReachableFrom)}</td><td>{E(risk)}</td></tr>\n");
            }
            h.Append("    </table>\n");
        }
        else
        {
            h.Append("    <p class=\"dim\">No listening program can be reached from other devices.</p>\n");
        }
        h.Append("  </div>\n");

        var devices = result.Extras["devices"] as JsonArray ?? [];
        if (devices.Count > 0)
        {
            h.Append("\n  <h2>Devices on your network</h2>\n  <div class=\"card\">\n    <table>\n      <tr><th>Name</th><th>Vendor</th><th>IP</th><th>MAC</th><th>Open services</th><th>Trusted</th></tr>\n");
            foreach (var d in devices)
            {
                var dn = Js.Truthy(Js.Get(d, "name")) ? Js.PyRepr(d!["name"]) : Js.Truthy(Js.Get(d, "randomized")) ? "Private address (likely a phone)" : "Unknown";
                var gw = Js.Truthy(Js.Get(d, "is_gateway")) ? " (router)" : "";
                var open = string.Join(", ", (Js.Get(d, "open_ports") as JsonArray ?? []).Select(x => Js.PyRepr(x)));
                h.Append(CultureInfo.InvariantCulture, $"      <tr><td>{E(dn)}{gw}</td>\n          <td>{E(Js.Get(d, "vendor"))}</td><td>{E(Js.Get(d, "ip"))}</td><td>{E(Js.Get(d, "mac"))}</td><td>{E(open)}</td><td>{(Js.Truthy(Js.Get(d, "trusted")) ? "yes" : "")}</td></tr>\n");
            }
            h.Append("    </table>\n  </div>\n");
        }

        var router = result.Extras["router"] as JsonObject;
        if (Js.Truthy(router))
        {
            h.Append("\n  <h2>Router</h2>\n  <div class=\"card\">\n");
            if (Js.Truthy(router!["found"]))
            {
                var rn = Js.Truthy(Js.Get(router, "friendly_name")) ? Js.PyRepr(router["friendly_name"])
                    : Js.Truthy(Js.Get(router, "model")) ? Js.PyRepr(router["model"]) : "Your router";
                var ext = Js.Truthy(Js.Get(router, "external_ip")) ? Js.PyRepr(router["external_ip"]) : "unknown";
                h.Append(CultureInfo.InvariantCulture, $"      <p><strong>{E(rn)}</strong> has UPnP on. Internet address: {E(ext)}.</p>\n");
                var mappings = Js.Get(router, "mappings") as JsonArray ?? [];
                if (mappings.Count > 0)
                {
                    h.Append("      <table><tr><th>Internet port</th><th>Forwarded to</th><th>Description</th></tr>\n");
                    foreach (var m in mappings)
                    {
                        h.Append(CultureInfo.InvariantCulture, $"<tr><td>{E(Js.Get(m, "protocol"))} {E(Js.Get(m, "external_port"))}</td><td>{E(Js.Get(m, "internal_client"))}:{E(Js.Get(m, "internal_port"))}</td><td>{E(Js.Get(m, "description"))}</td></tr>");
                    }
                    h.Append("\n      </table>\n");
                }
                else
                {
                    h.Append("<p class=\"dim\">No port forwards.</p>\n");
                }
            }
            else
            {
                h.Append("<p>UPnP port forwarding is not offered by the router.</p>\n");
            }
            h.Append("  </div>\n");
        }

        h.Append("\n  <h2>Changes made by SimplySec</h2>\n  <div class=\"card\">\n");
        if (changes.Count > 0)
        {
            h.Append("    <table><tr><th>#</th><th>Change</th><th>Status</th><th>Verified</th><th>When</th></tr>\n");
            foreach (var c in changes)
            {
                var verified = Js.IsNull(c["verified"]) ? "" : Js.Truthy(c["verified"]) ? "yes" : "NO";
                var when = Js.Truthy(c["reverted_at"]) ? Js.PyRepr(c["reverted_at"]) : Js.Truthy(c["applied_at"]) ? Js.PyRepr(c["applied_at"]) : "";
                h.Append(CultureInfo.InvariantCulture, $"      <tr><td>{E(c["id"])}</td><td>{E(c["summary"])}</td><td>{E(c["status"])}</td>\n          <td>{verified}</td><td>{E(When(when))}</td></tr>\n");
            }
            h.Append("    </table>\n");
        }
        else
        {
            h.Append("    <p class=\"dim\">SimplySec has not changed anything on this PC.</p>\n");
        }
        h.Append("  </div>\n\n  <h2>Accepted risks</h2>\n  <div class=\"card\">\n");
        if (accepted.Count > 0)
        {
            h.Append("    <ul>");
            foreach (var a in accepted)
            {
                var title = Js.Truthy(a["title"]) ? Js.PyRepr(a["title"]) : Js.PyRepr(a["keep_key"]);
                var created = Js.Str(a["created"]);
                h.Append(CultureInfo.InvariantCulture, $"<li>{E(title)} <span class=\"dim\">(since {E(created.Length > 10 ? created[..10] : created)})</span></li>");
            }
            h.Append("</ul>\n");
        }
        else
        {
            h.Append("    <p class=\"dim\">None.</p>\n");
        }
        h.Append("  </div>\n  <p class=\"dim\">This report describes the PC at the time of the scan. Findings marked \"Kept\" were accepted by the user and are not scored.</p>\n</main>\n</body>\n</html>\n");
        return h.ToString();
    }
}
