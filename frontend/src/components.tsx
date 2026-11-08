import { useEffect, useRef, useState } from "react";
import { Area, CartesianGrid, ComposedChart, Legend, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { getEval, labAttacks, labKernel, labRun, startEval, type LabAttackInfo, type LabResult } from "./api";
import { chartRows } from "./reduce";
import type { EvalResult, FeedItem, Model, PatchItem, Rate } from "./types";

export const pct = (r: Rate | null | undefined) => (r ? `${Math.round(r.rate * 100)}%` : "–");
export const ci = (r: Rate) => `${r.k}/${r.n} · 95% CI ${Math.round(r.lo * 100)}–${Math.round(r.hi * 100)}%`;

export function Kpis({ m }: { m: Model }) {
  const last = m.metrics[m.metrics.length - 1];
  const items: [string, string, string, string][] = [
    ["Attack success", last?.asr ? pct(last.asr) : "–", last?.asr ? ci(last.asr) : "waiting", "bad"],
    ["Benign utility", last ? `${last.utility.passed}/${last.utility.total}` : "–", last?.utility.baseline !== undefined ? `baseline ${last.utility.baseline}` : "baseline", "good"],
    ["Patches", last ? `${last.accepted} ✓ / ${last.rejected} ✗` : "–", "accepted / rejected", ""],
    ["False blocks", last ? String(last.falseBlocks) : "–", "on benign tasks", "warn"],
    ["Regression", last?.regression ? `${last.regression.failures}/${last.regression.library}` : "–", "old attacks that still work", "good"],
    ["Contained", last ? String(last.contained) : "–", "stopped by the sandbox", "acc"],
  ];
  return (
    <div className="kpis">
      {items.map(([t, v, s, tone]) => (
        <div className={`kpi ${tone}`} key={t}><div className="kpi-t">{t}</div><div className="kpi-v">{v}</div><div className="kpi-s">{s}</div></div>
      ))}
    </div>
  );
}

export function DualChart({ m }: { m: Model }) {
  const rows = chartRows(m.metrics);
  return (
    <div className="card">
      <h3>Attack success vs. utility, per round</h3>
      <p className="muted">Patches only count if utility holds. Shaded band = 95% Wilson interval for ASR.</p>
      <div style={{ height: 260 }}>
        <ResponsiveContainer>
          <ComposedChart data={rows} margin={{ top: 8, right: 12, bottom: 0, left: -12 }}>
            <CartesianGrid stroke="#262d38" strokeDasharray="3 3" />
            <XAxis dataKey="round" stroke="#8b98a9" label={{ value: "round (0 = baseline)", position: "insideBottom", offset: -2, fill: "#8b98a9", fontSize: 11 }} />
            <YAxis domain={[0, 100]} stroke="#8b98a9" unit="%" />
            <Tooltip contentStyle={{ background: "#161b22", border: "1px solid #262d38", borderRadius: 8 }} />
            <Legend />
            <Area dataKey="band" name="ASR 95% CI" stroke="none" fill="#ef7468" fillOpacity={0.15} isAnimationActive={false} />
            <Line dataKey="asr" name="Attack success %" stroke="#ef7468" strokeWidth={2.5} dot={{ r: 4 }} connectNulls isAnimationActive={false} />
            <Line dataKey="utility" name="Benign utility %" stroke="#3fb68b" strokeWidth={2.5} dot={{ r: 4 }} connectNulls isAnimationActive={false} />
          </ComposedChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

export function Feed({ items }: { items: FeedItem[] }) {
  const end = useRef<HTMLDivElement>(null);
  useEffect(() => { end.current?.scrollIntoView({ block: "end" }); }, [items.length]);
  return (
    <div className="card feed">
      <h3>Live feed</h3>
      <div className="feed-list">
        {items.length === 0 && <p className="muted">No events yet. Start a loop or replay a run.</p>}
        {items.map((f) => (
          <div key={f.seq} className={`feed-item ${f.tone} ${f.kind}`}>
            <div className="feed-title">{f.title}</div>
            {f.detail && <div className="feed-detail">{f.detail}</div>}
          </div>
        ))}
        <div ref={end} />
      </div>
    </div>
  );
}

const opLabel: Record<string, string> = {
  ADD_DENY: "Add deny rule", REMOVE_ALLOWED_VALUE: "Remove allowed value", TIGHTEN_PREFIX: "Tighten prefix",
  ADD_ARG_CONSTRAINT: "Add argument constraint", CAP_ARG_LENGTH: "Cap argument length",
};

export function Patches({ items }: { items: PatchItem[] }) {
  return (
    <div className="card">
      <h3>Policy patches <span className="muted">(narrowing only, utility-gated)</span></h3>
      {items.length === 0 && <p className="muted">No patches yet.</p>}
      <div className="patches">
        {items.map((p) => (
          <div key={p.seq} className={`patch ${p.status}`}>
            <div className="patch-head">
              <b>{opLabel[String(p.patch.op)] ?? String(p.patch.op)}</b>
              <span className={`badge ${p.status}`}>{p.status}</span>
            </div>
            <div className="muted">round {p.round} · {p.family} · by {p.source} · → v{p.version}</div>
            <pre>{JSON.stringify(p.patch, null, 1)}</pre>
            {p.reason && <div className="reason">{p.reason}</div>}
          </div>
        ))}
      </div>
    </div>
  );
}

export function Heldout({ loopId, version, disabled, fixed }: { loopId: string | null; version: number; disabled: boolean; fixed: boolean }) {
  const [res, setRes] = useState<EvalResult | null>(null);
  const [state, setState] = useState<"idle" | "running" | "failed">("idle");
  const [err, setErr] = useState("");
  const [n, setN] = useState(5);

  useEffect(() => { setRes(null); setState("idle"); setErr(""); }, [loopId]);

  async function run() {
    if (!loopId) return;
    setState("running"); setErr(""); setRes(null);
    try {
      const { eval_id } = await startEval(version, loopId, n, fixed);
      for (;;) {
        await new Promise((r) => setTimeout(r, 2000));
        const e = await getEval(eval_id);
        if (e.status === "done" && e.result) { setRes(e.result); setState("idle"); return; }
        if (e.status === "failed") throw new Error("evaluation failed");
      }
    } catch (e) { setErr(String(e instanceof Error ? e.message : e)); setState("failed"); }
  }

  const order = ["none", "prompt_guardrail", "static", "patched"];
  const names: Record<string, string> = { none: "No policy", prompt_guardrail: "Prompt guardrail", static: "Static policy", patched: "Patched policy (ours)" };
  return (
    <div className="card">
      <h3>Held-out attacks <span className="muted">(never shown to the patcher)</span></h3>
      <p className="muted">H1 encoded exfil via an allowed domain · H2 multi-step chain · H3 argument smuggling. Same attacks for every row.</p>
      <div className="row">
        <label>N per family <input type="number" min={1} max={30} value={n} onChange={(e) => setN(Math.max(1, Math.min(30, +e.target.value || 1)))} /></label>
        <button disabled={disabled || state === "running" || !loopId} onClick={run}>{state === "running" ? "Running…" : `Run on policy v${version}`}</button>
      </div>
      {err && <p className="err">{err}</p>}
      {res && (
        <div className="scroll-x"><table className="eval">
          <thead><tr><th>Config</th><th>Attack success</th><th>Utility</th><th>Damage*</th></tr></thead>
          <tbody>
            {order.filter((c) => res.configs[c]).map((c) => {
              const r = res.configs[c];
              return (
                <tr key={c} className={c === "patched" ? "ours" : ""}>
                  <td>{names[c]}</td>
                  <td><div className="bar"><div style={{ width: `${r.asr.rate * 100}%` }} /></div>{pct(r.asr)} <span className="muted">{ci(r.asr)}</span></td>
                  <td>{r.utility.passed}/{r.utility.total}</td>
                  <td>{r.damage}</td>
                </tr>
              );
            })}
          </tbody>
        </table></div>
      )}
      {res && <p className="muted small">*Damage weights are our published opinion. {res.note}</p>}
    </div>
  );
}

export function ContainmentLab() {
  const [attacks, setAttacks] = useState<LabAttackInfo[]>([]);
  const [results, setResults] = useState<Record<string, LabResult | "running" | string>>({});
  const [kernel, setKernel] = useState<{ runtime: string; output: string; available: boolean } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { labAttacks().then(setAttacks).catch(() => undefined); }, []);

  async function runAll() {
    setBusy(true);
    setResults(Object.fromEntries(attacks.map((a) => [a.id, "running"])));
    labKernel().then(setKernel).catch(() => undefined);
    await Promise.all(attacks.map(async (a) => {
      try {
        const r = await labRun(a.id);
        setResults((prev) => ({ ...prev, [a.id]: r }));
      } catch (e) {
        setResults((prev) => ({ ...prev, [a.id]: `error: ${e instanceof Error ? e.message : e}` }));
      }
    }));
    setBusy(false);
  }

  const done = Object.values(results).filter((r): r is LabResult => typeof r === "object");
  const escaped = done.filter((r) => r.status === "escaped").length;
  const contained = done.filter((r) => r.status === "contained").length;
  return (
    <div className="card">
      <h3>Containment Lab <span className="muted">(real attacks inside the real sandbox)</span></h3>
      <p className="muted">
        Each attack runs in a fresh container: no network, all capabilities dropped, read-only filesystem, 256 MB, pids limit, timeout, destroyed afterwards
        {done[0] ? ` · runtime: ${done[0].runtime}` : ""}. Verdicts are computed by code, not by an LLM.
      </p>
      <div className="row">
        <button className="primary" disabled={busy || attacks.length === 0} onClick={runAll}>{busy ? "Attacking…" : `Run ${attacks.length} attacks`}</button>
        {done.length > 0 && <b className={escaped ? "err" : "ok"}>{contained} contained · {escaped} escaped · {done.length - contained - escaped} other</b>}
      </div>
      <div className="lab">
        {attacks.map((a) => {
          const r = results[a.id];
          const res = typeof r === "object" ? r : null;
          const status = res ? res.status : r === "running" ? "running" : r ? "error" : "idle";
          return (
            <div key={a.id} className={`lab-item ${status}`}>
              <div className="patch-head"><b>{a.title}</b><span className={`badge ${status}`}>{status}</span></div>
              <div className="muted small">{a.goal}</div>
              {res && <pre>{res.evidence}</pre>}
              {res && <div className="muted small">exit {res.exit_code} · {res.duration_s}s</div>}
              {typeof r === "string" && r !== "running" && <div className="reason">{r}</div>}
              <details><summary className="muted small">attack code</summary><pre>{a.code}</pre></details>
            </div>
          );
        })}
      </div>
      {kernel && (
        <div className="kernel">
          <div className="muted small">What the sandboxed process sees as its kernel (runtime: {kernel.runtime})</div>
          <pre>{kernel.available ? kernel.output : "sandbox unavailable"}</pre>
        </div>
      )}
    </div>
  );
}
