import type { LoopEvent, Model, PatchItem, RoundMetrics } from "./types";

export const emptyModel = (): Model => ({
  status: "idle", round: 0, policyVersion: 0, metrics: [], feed: [], patches: [],
});

const trunc = (s: unknown, n = 140) => {
  const t = String(s ?? "");
  return t.length > n ? t.slice(0, n) + "…" : t;
};

/** Pure reducer: the same code drives the live stream and the replay. */
export function reduce(events: LoopEvent[]): Model {
  const m = emptyModel();
  if (events.length) m.status = "running";
  const patchBySeqKey = new Map<string, PatchItem>();

  for (const e of events) {
    const d = e.data ?? {};
    switch (e.type) {
      case "round_start":
        m.round = d.round;
        m.policyVersion = d.policy_version;
        m.feed.push({ seq: e.seq, kind: "round", tone: "neutral", title: `Round ${d.round} · policy v${d.policy_version}` });
        break;
      case "note":
        m.feed.push({ seq: e.seq, kind: "note", tone: "neutral", title: String(d.text ?? "") });
        break;
      case "attack":
        m.feed.push({ seq: e.seq, kind: "attack", tone: "warn", title: `Attack ${d.family} (${d.source}, via ${d.carrier})`, detail: trunc(d.payload, 200) });
        m.lastBreach = { family: d.family, payload: d.payload };
        break;
      case "tool_call":
        m.feed.push({
          seq: e.seq, kind: "tool", tone: d.allowed ? "neutral" : "good",
          title: `${d.allowed ? "allowed" : "BLOCKED"} ${d.tool}`,
          detail: d.allowed ? trunc(JSON.stringify(d.args), 120) : `${d.rule ?? ""} · ${trunc(d.reason, 100)}`,
        });
        break;
      case "verdict":
        m.feed.push({
          seq: e.seq, kind: "verdict", tone: d.breached ? "bad" : "good",
          title: d.breached ? `BREACH · damage ${d.damage}` : "Contained / no breach",
          detail: d.breached ? (d.breaches as string[]).join(", ") : trunc(d.why, 100),
        });
        break;
      case "patch_proposed": {
        const p: PatchItem = { seq: e.seq, round: d.round, family: d.family, source: d.source, version: d.version, patch: d.patch, status: "proposed" };
        m.patches.push(p);
        patchBySeqKey.set(`${d.round}:${d.family}:${d.version}`, p);
        m.feed.push({ seq: e.seq, kind: "patch", tone: "warn", title: `Patch proposed (${d.source}) → v${d.version}`, detail: JSON.stringify(d.patch) });
        break;
      }
      case "patch_accepted": {
        const p = patchBySeqKey.get(`${d.round}:${d.family}:${d.version}`);
        if (p) p.status = "accepted";
        m.policyVersion = d.version;
        m.feed.push({ seq: e.seq, kind: "patch", tone: "good", title: `Patch ACCEPTED → v${d.version}`, detail: `utility ${d.utility.passed}/${d.utility.total}` });
        break;
      }
      case "patch_rejected": {
        const open = [...m.patches].reverse().find((p) => p.status === "proposed" && p.round === d.round && p.family === d.family);
        if (open) { open.status = "rejected"; open.reason = d.reason; }
        m.feed.push({ seq: e.seq, kind: "patch", tone: "bad", title: "Patch REJECTED", detail: d.reason });
        break;
      }
      case "metrics": {
        const r: RoundMetrics = {
          round: d.round, policyVersion: d.policy_version, asr: d.asr ?? null,
          utility: d.utility, damage: d.damage ?? 0, contained: d.contained ?? 0, falseBlocks: d.false_blocks ?? 0,
          accepted: d.patches_accepted ?? 0, rejected: d.patches_rejected ?? 0, regression: d.regression, diversity: d.attacker_diversity,
        };
        const i = m.metrics.findIndex((x) => x.round === r.round);
        if (i >= 0) m.metrics[i] = r; else m.metrics.push(r);
        break;
      }
      case "done":
        m.status = d.status === "failed" ? "failed" : "done";
        m.feed.push({ seq: e.seq, kind: "done", tone: d.status === "failed" ? "bad" : "good", title: d.status === "failed" ? `Failed: ${d.error}` : `Done · final policy v${d.final_policy_version}` });
        break;
      default:
        break;
    }
  }
  return m;
}

/** Chart rows in percent. Round 0 is the utility baseline (no ASR yet). */
export function chartRows(metrics: RoundMetrics[]) {
  return metrics.map((r) => ({
    round: r.round,
    asr: r.asr ? Math.round(r.asr.rate * 100) : null,
    band: r.asr ? [Math.round(r.asr.lo * 100), Math.round(r.asr.hi * 100)] : null,
    utility: r.utility.total ? Math.round((r.utility.passed / r.utility.total) * 100) : null,
  }));
}
