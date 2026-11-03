using System.Text.Json.Nodes;
using SimplySec.App.Infrastructure;
using SimplySec.Core;
using SimplySec.Core.Checks;
using SimplySec.Core.Engine;
using SimplySec.Core.Model;

namespace SimplySec.App.ViewModels;

/// <summary>
/// The preview dialog's content and choices (port of PreviewDialog's logic in fix_dialogs.py).
/// Each fix has its own tick box; fixes that are in use right now start unticked. A warning's
/// offered fix (e.g. "mark this network Private first") is listed once and starts unticked.
/// </summary>
public sealed class PreviewModel
{
    public sealed class Item(PlannedFix fix, Finding? finding)
    {
        public PlannedFix Fix { get; } = fix;
        public Finding? Finding { get; } = finding;
        public bool InUse => Fix.Impact is not null && Fix.Impact.Level == ImpactLevel.InUse;
        public bool Included { get; set; } = !(fix.Impact is not null && fix.Impact.Level == ImpactLevel.InUse);
        /// <summary>Offers shown under this item (already de-duplicated across the plan).</summary>
        public List<Offer> Offers { get; } = [];
    }

    public sealed class Offer(FixWarning warning)
    {
        public FixWarning Warning { get; } = warning;
        public string Label => Warning.OfferLabel.Length > 0 ? Warning.OfferLabel : "Do this first";
        public bool Ticked { get; set; }
    }

    public Plan Plan { get; }
    public bool IsAdmin { get; }
    public List<Item> Items { get; } = [];
    public bool RestorePoint { get; set; }

    public PreviewModel(Plan plan, bool isAdmin, IReadOnlyDictionary<string, Finding>? findings = null)
    {
        Plan = plan;
        IsAdmin = isAdmin;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var p in plan.Items)
        {
            Finding? finding = null;
            findings?.TryGetValue(p.FindingId ?? "", out finding);
            var item = new Item(p, finding);
            foreach (var w in p.Warnings)
            {
                if (w.OfferFix is null || !seen.Add($"{w.OfferFix}:{SortedJson(w.OfferParams)}"))
                {
                    continue;
                }
                item.Offers.Add(new Offer(w));
            }
            Items.Add(item);
        }
    }

    public int IncludedCount => Items.Count(i => i.Included);

    public string ApplyText => IncludedCount switch
    {
        0 => "Nothing ticked",
        1 => "Apply 1 change",
        var n => $"Apply {n} changes",
    };

    public string Note => "Every change is recorded with its previous value and can be undone on the Changes page."
        + (IsAdmin ? "" : " Windows will ask for administrator permission to apply them.");

    public PreviewChoice Choice(bool accepted) => new(
        accepted,
        RestorePoint,
        Items.SelectMany(i => i.Offers).Where(o => o.Ticked).Select(o => o.Warning).ToList(),
        Items.Select((item, i) => (item, i)).Where(x => x.item.Included).Select(x => x.i).ToList());

    private static string SortedJson(JsonObject o) =>
        string.Join(",", o.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => $"{kv.Key}={kv.Value?.ToJsonString()}"));
}
