using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using SimplySec.Core.Checks;
using SimplySec.Core.Compat;
using SimplySec.Core.Engine;
using SimplySec.Core.Model;

namespace SimplySec.Core.Storage;

public sealed record ScanSummary(long Id, string Ts, string Kind, int Score, string Grade);

/// <summary>What changed between two stored scans.</summary>
public sealed class Comparison
{
    /// <summary>Risk score change: positive means riskier.</summary>
    public int ScoreChange { get; init; }
    public List<JsonObject> NewFindings { get; init; } = [];
    public List<JsonObject> ResolvedFindings { get; init; } = [];
    public List<string> NewListeners { get; init; } = [];
    public List<string> GoneListeners { get; init; } = [];
    public List<JsonObject> NewDevices { get; init; } = [];

    public bool Empty => ScoreChange == 0 && NewFindings.Count == 0 && ResolvedFindings.Count == 0
                         && NewListeners.Count == 0 && GoneListeners.Count == 0 && NewDevices.Count == 0;

    public JsonObject ToJson() => new()
    {
        ["score_change"] = ScoreChange,
        ["new_findings"] = new JsonArray(NewFindings.Select(f => f.DeepClone()).ToArray()),
        ["resolved_findings"] = new JsonArray(ResolvedFindings.Select(f => f.DeepClone()).ToArray()),
        ["new_listeners"] = Js.StrArray(NewListeners),
        ["gone_listeners"] = Js.StrArray(GoneListeners),
        ["new_devices"] = new JsonArray(NewDevices.Select(f => f.DeepClone()).ToArray()),
    };
}

/// <summary>
/// Per-user history (%LOCALAPPDATA%\SimplySec\history.db): scans, devices, settings and accepted
/// risks ("Keep"). Same schema and JSON as Python v2.
/// </summary>
public sealed class History
{
    public const int KeepScans = 365;

    private const string Schema = """
        CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            kind TEXT NOT NULL,
            score INTEGER NOT NULL,
            grade TEXT NOT NULL,
            data TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS accepted(
            keep_key TEXT PRIMARY KEY,
            width INTEGER NOT NULL,
            title TEXT,
            created TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS devices(
            mac TEXT PRIMARY KEY,
            ip TEXT,
            name TEXT,
            vendor TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            trusted INTEGER NOT NULL DEFAULT 0,
            label TEXT,
            data TEXT
        );
        """;

    public string Path { get; }

    public History(string path)
    {
        Path = path;
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path))!);
        Exec(Schema);
        MigrateScoreScale();
    }

    private SqliteConnection Connect()
    {
        var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Path, Pooling = false }.ToString());
        db.Open();
        return db;
    }

    private void Exec(string sql, params object?[] args)
    {
        using var db = Connect();
        Exec(db, null, sql, args);
    }

    private static long Exec(SqliteConnection db, SqliteTransaction? tx, string sql, params object?[] args)
    {
        using var cmd = db.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        for (var i = 0; i < args.Length; i++)
        {
            cmd.Parameters.AddWithValue($"$p{i}", args[i] ?? DBNull.Value);
        }
        return cmd.ExecuteNonQuery();
    }

    private List<T> Rows<T>(string sql, Func<SqliteDataReader, T> map, params object[] args)
    {
        using var db = Connect();
        using var cmd = db.CreateCommand();
        cmd.CommandText = sql;
        for (var i = 0; i < args.Length; i++)
        {
            cmd.Parameters.AddWithValue($"$p{i}", args[i]);
        }
        using var reader = cmd.ExecuteReader();
        var output = new List<T>();
        while (reader.Read())
        {
            output.Add(map(reader));
        }
        return output;
    }

    /// <summary>Scans saved before the risk score (100 = clean) get 100 - old, so trends stay valid.</summary>
    private void MigrateScoreScale()
    {
        if (Js.PyEquals(GetSetting("score_scale"), JsonValue.Create("risk")))
        {
            return;
        }
        using (var db = Connect())
        {
            using var tx = db.BeginTransaction();
            var rows = new List<(long Id, int Score, string Data)>();
            using (var cmd = db.CreateCommand())
            {
                cmd.Transaction = tx;
                cmd.CommandText = "SELECT id, score, data FROM scans";
                using var r = cmd.ExecuteReader();
                while (r.Read())
                {
                    rows.Add((r.GetInt64(0), r.GetInt32(1), r.GetString(2)));
                }
            }
            foreach (var (id, score, text) in rows)
            {
                var updated = 100 - score;
                var data = JsonNode.Parse(text)!.AsObject();
                List<Finding> findings;
                try
                {
                    findings = (data["findings"] as JsonArray ?? []).Select(f => Finding.FromJson(f!)).ToList();
                }
                catch (Exception e) when (e is KeyNotFoundException or ArgumentException or InvalidOperationException)
                {
                    findings = [];
                }
                var letter = Scoring.Grade(updated, findings);
                data["score"] = updated;
                data["grade"] = letter;
                Exec(db, tx, "UPDATE scans SET score=$p0, grade=$p1, data=$p2 WHERE id=$p3", updated, letter, data.ToJsonString(), id);
            }
            tx.Commit();
        }
        SetSetting("score_scale", JsonValue.Create("risk"));
    }

    // ------------------------------------------------------------------ scans

    public long SaveScan(ScanResult result, string kind = "manual")
    {
        var data = result.ToJson(includeFacts: false);
        using var db = Connect();
        using var tx = db.BeginTransaction();
        Exec(db, tx, "INSERT INTO scans(ts, kind, score, grade, data) VALUES ($p0, $p1, $p2, $p3, $p4)",
            result.Started, kind, result.Score, result.Grade, data.ToJsonString());
        long id;
        using (var cmd = db.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = "SELECT last_insert_rowid()";
            id = (long)(cmd.ExecuteScalar() ?? 0L);
        }
        Exec(db, tx, "DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT $p0)", KeepScans);
        tx.Commit();
        return id;
    }

    public List<ScanSummary> Scans(int limit = 200) =>
        Rows("SELECT id, ts, kind, score, grade FROM scans ORDER BY id DESC LIMIT $p0",
            r => new ScanSummary(r.GetInt64(0), r.GetString(1), r.GetString(2), r.GetInt32(3), r.GetString(4)), limit);

    public JsonObject? ScanData(long scanId) =>
        Rows("SELECT data FROM scans WHERE id=$p0", r => JsonNode.Parse(r.GetString(0))!.AsObject(), scanId).FirstOrDefault();

    public List<JsonObject> Latest(int n = 2) =>
        Rows("SELECT data FROM scans ORDER BY id DESC LIMIT $p0", r => JsonNode.Parse(r.GetString(0))!.AsObject(), n);

    public JsonObject? PreviousTo(long scanId) =>
        Rows("SELECT data FROM scans WHERE id < $p0 ORDER BY id DESC LIMIT 1", r => JsonNode.Parse(r.GetString(0))!.AsObject(), scanId).FirstOrDefault();

    // ------------------------------------------------------------------ accepted risks

    public void Accept(string keepKey, int width, string title = "") =>
        Exec("INSERT INTO accepted(keep_key, width, title, created) VALUES ($p0, $p1, $p2, $p3) ON CONFLICT(keep_key) DO UPDATE SET width=excluded.width, title=excluded.title",
            keepKey, width, title, PyTime.NowIsoSeconds());

    public void Unaccept(string keepKey) => Exec("DELETE FROM accepted WHERE keep_key=$p0", keepKey);

    public List<JsonObject> Accepted() => Rows("SELECT keep_key, width, title, created FROM accepted ORDER BY created", r => new JsonObject
    {
        ["keep_key"] = r.GetString(0),
        ["width"] = r.GetInt64(1),
        ["title"] = r.IsDBNull(2) ? null : r.GetString(2),
        ["created"] = r.GetString(3),
    });

    public Dictionary<string, int> AcceptedWidths()
    {
        var output = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var a in Accepted())
        {
            output[Js.Str(a["keep_key"])] = Js.Int(a["width"]);
        }
        return output;
    }

    // ------------------------------------------------------------------ settings

    public JsonNode? GetSetting(string key, JsonNode? def = null)
    {
        var rows = Rows("SELECT value FROM settings WHERE key=$p0", r => r.GetString(0), key);
        return rows.Count > 0 ? JsonNode.Parse(rows[0]) : def;
    }

    public void SetSetting(string key, JsonNode? value) =>
        Exec("INSERT INTO settings(key, value) VALUES ($p0, $p1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            key, value is null ? "null" : value.ToJsonString());

    // ------------------------------------------------------------------ devices

    /// <summary>Insert or refresh a device. Returns true if it was never seen before.</summary>
    public bool UpsertDevice(string mac, string ip, string name, string vendor, JsonObject data)
    {
        var now = PyTime.NowIsoSeconds();
        using var db = Connect();
        using var tx = db.BeginTransaction();
        bool exists;
        using (var cmd = db.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = "SELECT mac FROM devices WHERE mac=$p0";
            cmd.Parameters.AddWithValue("$p0", mac);
            exists = cmd.ExecuteScalar() is not null;
        }
        if (!exists)
        {
            Exec(db, tx, "INSERT INTO devices(mac, ip, name, vendor, first_seen, last_seen, data) VALUES ($p0, $p1, $p2, $p3, $p4, $p5, $p6)",
                mac, ip, name, vendor, now, now, data.ToJsonString());
        }
        else
        {
            Exec(db, tx, "UPDATE devices SET ip=$p0, name=COALESCE(NULLIF($p1, ''), name), vendor=COALESCE(NULLIF($p2, ''), vendor), last_seen=$p3, data=$p4 WHERE mac=$p5",
                ip, name, vendor, now, data.ToJsonString(), mac);
        }
        tx.Commit();
        return !exists;
    }

    public List<JsonObject> Devices() => Rows("SELECT mac, ip, name, vendor, first_seen, last_seen, trusted, label, data FROM devices ORDER BY last_seen DESC", r => new JsonObject
    {
        ["mac"] = r.GetString(0),
        ["ip"] = r.IsDBNull(1) ? null : r.GetString(1),
        ["name"] = r.IsDBNull(2) ? null : r.GetString(2),
        ["vendor"] = r.IsDBNull(3) ? null : r.GetString(3),
        ["first_seen"] = r.GetString(4),
        ["last_seen"] = r.GetString(5),
        ["trusted"] = r.GetInt64(6) != 0,
        ["label"] = r.IsDBNull(7) ? null : r.GetString(7),
        ["data"] = JsonNode.Parse(r.IsDBNull(8) || r.GetString(8).Length == 0 ? "{}" : r.GetString(8)),
    });

    public void SetDeviceTrusted(string mac, bool trusted) => Exec("UPDATE devices SET trusted=$p0 WHERE mac=$p1", trusted ? 1 : 0, mac);

    public void SetDeviceLabel(string mac, string label) => Exec("UPDATE devices SET label=$p0 WHERE mac=$p1", label, mac);

    // ------------------------------------------------------------------ comparison

    private static OrderedDictionary<string, JsonObject> ScoredFindings(JsonNode? findings)
    {
        var output = new OrderedDictionary<string, JsonObject>(StringComparer.Ordinal);
        foreach (var f in findings as JsonArray ?? [])
        {
            if (Js.PyEquals(Js.Get(f, "status"), JsonValue.Create("open")) && !Js.PyEquals(Js.Get(f, "severity"), JsonValue.Create("info")))
            {
                output[Js.Str(f!["id"])] = f.AsObject();
            }
        }
        return output;
    }

    private static HashSet<string> ListenerKeys(JsonNode d)
    {
        var output = new HashSet<string>(StringComparer.Ordinal);
        foreach (var p in Js.Get(d, "ports") as JsonArray ?? [])
        {
            var v = Js.Str(Js.Get(p, "verdict"));
            if (v is "reachable" or "uncertain")
            {
                output.Add($"{PyStr.Upper(Js.Str(p!["protocol"]))} {Js.PyRepr(p["port"])} ({Js.PyRepr(p["process"])})");
            }
        }
        return output;
    }

    private static readonly string[] SevOrder = ["info", "low", "medium", "high", "critical"];

    private static List<JsonNode?> ExtrasDevices(JsonNode d) =>
        (Js.Get(Js.Get(d, "extras") ?? new JsonObject(), "devices") as JsonArray ?? []).ToList();

    /// <summary>What changed between two stored scans (dicts from ScanResult.ToJson).</summary>
    public static Comparison Compare(JsonNode? old, JsonNode @new)
    {
        if (old is null)
        {
            return new Comparison();
        }
        var a = ScoredFindings(Js.Get(old, "findings"));
        var b = ScoredFindings(Js.Get(@new, "findings"));
        var newF = b.Where(kv => !a.ContainsKey(kv.Key)
                || Array.IndexOf(SevOrder, Js.Str(kv.Value["severity"])) > Array.IndexOf(SevOrder, Js.Str(a[kv.Key]["severity"])))
            .Select(kv => kv.Value).ToList();
        var resolved = a.Where(kv => !b.ContainsKey(kv.Key)).Select(kv => kv.Value).ToList();
        var la = ListenerKeys(old);
        var lb = ListenerKeys(@new);
        var oldDev = ExtrasDevices(old).Select(d => Js.StrOrNull(Js.Get(d, "mac"))).ToHashSet();
        var newDev = ExtrasDevices(@new).Where(d => !oldDev.Contains(Js.StrOrNull(Js.Get(d, "mac"))) && oldDev.Count > 0)
            .Select(d => d!.AsObject()).ToList();
        return new Comparison
        {
            ScoreChange = Js.Int(GetOr(@new, "score")) - Js.Int(GetOr(old, "score")),
            NewFindings = newF,
            ResolvedFindings = resolved,
            NewListeners = lb.Except(la).Order(StringComparer.Ordinal).ToList(),
            GoneListeners = la.Except(lb).Order(StringComparer.Ordinal).ToList(),
            NewDevices = newDev,
        };
    }

    private static JsonNode GetOr(JsonNode d, string key) => Js.Get(d, key) ?? JsonValue.Create(0);
}
