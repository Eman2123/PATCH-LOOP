import { useEffect, useMemo, useState } from "react";
import { getToken, health, listLoops, setToken, startLoop } from "./api";
import { DualChart, Feed, Heldout, Kpis, Patches } from "./components";
import { reduce } from "./reduce";
import { useEvents, type Source } from "./useEvents";

type LoopRow = { id: string; created: number; status: string };

export default function App() {
  const [source, setSource] = useState<Source>(null);
  const [rounds, setRounds] = useState(4);
  const [per, setPer] = useState(5);
  const [fixed, setFixed] = useState(false);
  const [template, setTemplate] = useState(false);
  const [token, setTok] = useState(getToken());
  const [loops, setLoops] = useState<LoopRow[]>([]);
  const [pick, setPick] = useState("");
  const [speed, setSpeed] = useState(4);
  const [err, setErr] = useState("");
  const [info, setInfo] = useState("");

  const { events, error } = useEvents(source);
  const model = useMemo(() => reduce(events), [events]);
  const refresh = () => listLoops().then(setLoops).catch(() => undefined);

  useEffect(() => {
    refresh();
    health().then((h) => setInfo(`backend ok · tool mode ${h.tool_mode}${h.busy ? " · busy" : ""}`)).catch(() => setInfo("backend unreachable"));
  }, []);
  useEffect(() => { if (model.status === "done" || model.status === "failed") refresh(); }, [model.status]);

  async function start() {
    setErr(""); setToken(token);
    try {
      const { loop_id } = await startLoop({ rounds, attacks_per_round: per, use_fixed_attacks: fixed, template_patcher_only: template });
      setSource({ mode: "live", loopId: loop_id, speed: 1 });
    } catch (e) { setErr(String(e instanceof Error ? e.message : e)); }
  }

  const running = model.status === "running" && source?.mode === "live";
  const canEval = model.status === "done" && source !== null;

  return (
    <div className="app">
      <header>
        <div>
          <h1>PATCH LOOP</h1>
          <p className="tag">Attack → Detect → Patch → Verify → Generalize. Adaptive policy refinement, no model training.</p>
        </div>
        <div className={`pill ${model.status}`}>{model.status}{model.round ? ` · round ${model.round}` : ""} · policy v{model.policyVersion}</div>
      </header>

      <section className="card controls">
        <label>Rounds <input type="number" min={1} max={8} value={rounds} onChange={(e) => setRounds(+e.target.value || 1)} /></label>
        <label>Attacks / round <input type="number" min={1} max={20} value={per} onChange={(e) => setPer(+e.target.value || 1)} /></label>
        <label className="chk"><input type="checkbox" checked={fixed} onChange={(e) => setFixed(e.target.checked)} /> fixed payloads</label>
        <label className="chk"><input type="checkbox" checked={template} onChange={(e) => setTemplate(e.target.checked)} /> template patcher</label>
        <label>Admin token <input type="password" value={token} placeholder="if required" onChange={(e) => setTok(e.target.value)} /></label>
        <button className="primary" disabled={running} onClick={start}>{running ? "Running…" : "Start loop"}</button>
        <span className="sep" />
        <select value={pick} onChange={(e) => setPick(e.target.value)} onFocus={refresh}>
          <option value="">Past runs…</option>
          {loops.map((l) => <option key={l.id} value={l.id}>{l.id} · {l.status} · {new Date(l.created * 1000).toLocaleTimeString()}</option>)}
        </select>
        <select value={speed} onChange={(e) => setSpeed(+e.target.value)}>{[1, 2, 4, 8, 16].map((s) => <option key={s} value={s}>{s}×</option>)}</select>
        <button disabled={!pick} onClick={() => setSource({ mode: "replay", loopId: pick, speed })}>Replay</button>
        <button disabled={!pick} onClick={() => setSource({ mode: "live", loopId: pick, speed: 1 })}>Open</button>
      </section>
      {(err || error) && <p className="err">{err || error}</p>}
      <p className="muted small">{info}</p>

      <Kpis m={model} />
      <div className="grid">
        <div className="col">
          <DualChart m={model} />
          <Heldout loopId={source?.loopId ?? null} version={model.policyVersion} disabled={!canEval} fixed={fixed} />
          <Patches items={model.patches} />
        </div>
        <Feed items={model.feed} />
      </div>
      <footer className="muted small">Preliminary results, small N. Verifier is deterministic (state-diff), never an LLM. Damage weights are an opinion.</footer>
    </div>
  );
}
