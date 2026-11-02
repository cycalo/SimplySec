using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using SimplySec.Core.Checks;
using SimplySec.Core.Compat;
using SimplySec.Core.Model;

namespace SimplySec.Core.Storage;

public sealed class ChangeRecord
{
    public long Id { get; init; }
    public long BatchId { get; init; }
    public int Seq { get; init; }
    public string Kind { get; init; } = "";
    public JsonObject Params { get; init; } = [];
    public string Summary { get; init; } = "";
    public string? FixId { get; init; }
    public string? FindingId { get; init; }
    public JsonObject? Before { get; init; }
    public string Status { get; init; } = "";
    public bool? Verified { get; init; }
    public string? Error { get; init; }
    public string? AppliedAt { get; init; }
    public string? RevertedAt { get; init; }

    public ActionSpec Spec => new(Kind, Params, Summary);
    public bool Active => Status == Journal.Applied;

    public JsonObject ToJson() => new()
    {
        ["id"] = Id,
        ["batch_id"] = BatchId,
        ["seq"] = Seq,
        ["kind"] = Kind,
        ["params"] = Params.DeepClone(),
        ["summary"] = Summary,
        ["fix_id"] = FixId,
        ["finding_id"] = FindingId,
        ["before"] = Before?.DeepClone(),
        ["status"] = Status,
        ["verified"] = Verified,
        ["error"] = Error,
        ["applied_at"] = AppliedAt,
        ["reverted_at"] = RevertedAt,
    };
}

public sealed record BatchRecord(long Id, string Created, string Title, List<string> Fixes, string? Backup, string? User);

/// <summary>
/// The change journal (%ProgramData%\SimplySec\simplysec.db): every change with its before-state.
/// Same schema as Python v2, so either version can undo the other's changes.
/// </summary>
public sealed class Journal
{
    public const string Pending = "pending";
    public const string Applied = "applied";
    public const string Failed = "failed";
    public const string Reverted = "reverted";
    public const string RevertFailed = "revert_failed";

    private const string Schema = """
        CREATE TABLE IF NOT EXISTS batches(
            id INTEGER PRIMARY KEY,
            created TEXT NOT NULL,
            title TEXT NOT NULL,
            fixes TEXT NOT NULL,
            backup TEXT,
            user TEXT
        );
        CREATE TABLE IF NOT EXISTS changes(
            id INTEGER PRIMARY KEY,
            batch_id INTEGER NOT NULL REFERENCES batches(id),
            seq INTEGER NOT NULL,
            kind TEXT NOT NULL,
            params TEXT NOT NULL,
            summary TEXT NOT NULL,
            fix_id TEXT,
            finding_id TEXT,
            before TEXT,
            status TEXT NOT NULL,
            verified INTEGER,
            error TEXT,
            applied_at TEXT,
            reverted_at TEXT
        );
        CREATE INDEX IF NOT EXISTS changes_batch ON changes(batch_id);
        """;

    public string Path { get; }
    public bool ReadOnly { get; }

    public Journal(string path, bool readOnly = false)
    {
        Path = path;
        ReadOnly = readOnly;
        if (!readOnly)
        {
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path))!);
            using var db = Connect();
            using var cmd = db.CreateCommand();
            cmd.CommandText = Schema;
            cmd.ExecuteNonQuery();
        }
    }

    private SqliteConnection Connect()
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = Path,
            Mode = ReadOnly ? SqliteOpenMode.ReadOnly : SqliteOpenMode.ReadWriteCreate,
            Pooling = false,
        };
        var db = new SqliteConnection(builder.ToString());
        db.Open();
        return db;
    }

    public bool Available => !ReadOnly || File.Exists(Path);

    private long Write(string sql, params object?[] args)
    {
        if (ReadOnly)
        {
            throw new UnauthorizedAccessException("the change journal is read-only without administrator rights");
        }
        using var db = Connect();
        using var tx = db.BeginTransaction();
        using var cmd = db.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        for (var i = 0; i < args.Length; i++)
        {
            cmd.Parameters.AddWithValue($"$p{i}", args[i] ?? DBNull.Value);
        }
        cmd.ExecuteNonQuery();
        using var idCmd = db.CreateCommand();
        idCmd.Transaction = tx;
        idCmd.CommandText = "SELECT last_insert_rowid()";
        var id = (long)(idCmd.ExecuteScalar() ?? 0L);
        tx.Commit();
        return id;
    }

    private static string Dumps(JsonNode? n) => n is null ? "null" : n.ToJsonString();

    // ------------------------------------------------------------------ writing

    public long BeginBatch(string title, List<string> fixes, string user = "") =>
        Write("INSERT INTO batches(created, title, fixes, user) VALUES ($p0, $p1, $p2, $p3)",
            PyTime.NowIsoSeconds(), title, Js.StrArray(fixes).ToJsonString(), user);

    public void SetBackup(long batchId, string path) =>
        Write("UPDATE batches SET backup=$p0 WHERE id=$p1", path, batchId);

    public long AddChange(long batchId, int seq, ActionSpec spec, JsonObject? before, string? fixId = null, string? findingId = null) =>
        Write("INSERT INTO changes(batch_id, seq, kind, params, summary, fix_id, finding_id, before, status) VALUES ($p0, $p1, $p2, $p3, $p4, $p5, $p6, $p7, $p8)",
            batchId, seq, spec.Kind, Dumps(spec.Params), spec.Summary, fixId, findingId, Dumps(before), Pending);

    public void MarkApplied(long id) =>
        Write("UPDATE changes SET status=$p0, applied_at=$p1, error=NULL WHERE id=$p2", Applied, PyTime.NowIsoSeconds(), id);

    public void MarkFailed(long id, string error) =>
        Write("UPDATE changes SET status=$p0, error=$p1 WHERE id=$p2", Failed, CheckHelpers.Truncate(error, 2000), id);

    public void SetVerified(long id, bool ok) =>
        Write("UPDATE changes SET verified=$p0 WHERE id=$p1", ok ? 1 : 0, id);

    public void MarkReverted(long id) =>
        Write("UPDATE changes SET status=$p0, reverted_at=$p1, error=NULL WHERE id=$p2", Reverted, PyTime.NowIsoSeconds(), id);

    public void MarkRevertFailed(long id, string error) =>
        Write("UPDATE changes SET status=$p0, error=$p1 WHERE id=$p2", RevertFailed, CheckHelpers.Truncate(error, 2000), id);

    // ------------------------------------------------------------------ reading

    private List<T> Rows<T>(string sql, Func<SqliteDataReader, T> map, params object[] args)
    {
        if (!Available)
        {
            return [];
        }
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

    private static string? Text(SqliteDataReader r, string col) =>
        r.IsDBNull(r.GetOrdinal(col)) ? null : r.GetString(r.GetOrdinal(col));

    private static ChangeRecord MapChange(SqliteDataReader r)
    {
        var before = Text(r, "before");
        var verifiedOrd = r.GetOrdinal("verified");
        return new ChangeRecord
        {
            Id = r.GetInt64(r.GetOrdinal("id")),
            BatchId = r.GetInt64(r.GetOrdinal("batch_id")),
            Seq = r.GetInt32(r.GetOrdinal("seq")),
            Kind = r.GetString(r.GetOrdinal("kind")),
            Params = JsonNode.Parse(r.GetString(r.GetOrdinal("params"))) as JsonObject ?? [],
            Summary = r.GetString(r.GetOrdinal("summary")),
            FixId = Text(r, "fix_id"),
            FindingId = Text(r, "finding_id"),
            Before = string.IsNullOrEmpty(before) ? null : JsonNode.Parse(before) as JsonObject,
            Status = r.GetString(r.GetOrdinal("status")),
            Verified = r.IsDBNull(verifiedOrd) ? null : r.GetInt64(verifiedOrd) != 0,
            Error = Text(r, "error"),
            AppliedAt = Text(r, "applied_at"),
            RevertedAt = Text(r, "reverted_at"),
        };
    }

    public List<ChangeRecord> Changes(long? batchId = null) => batchId is null
        ? Rows("SELECT * FROM changes ORDER BY id", MapChange)
        : Rows("SELECT * FROM changes WHERE batch_id=$p0 ORDER BY id", MapChange, batchId.Value);

    public ChangeRecord? Change(long id) => Rows("SELECT * FROM changes WHERE id=$p0", MapChange, id).FirstOrDefault();

    public List<ChangeRecord> ActiveChanges() => Changes().Where(c => c.Status is Applied or RevertFailed).ToList();

    public List<BatchRecord> Batches() => Rows("SELECT * FROM batches ORDER BY id", r => new BatchRecord(
        r.GetInt64(r.GetOrdinal("id")),
        r.GetString(r.GetOrdinal("created")),
        r.GetString(r.GetOrdinal("title")),
        Js.StrList(JsonNode.Parse(r.GetString(r.GetOrdinal("fixes")))),
        Text(r, "backup"),
        Text(r, "user")));
}
