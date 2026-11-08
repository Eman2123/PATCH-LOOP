import { useEffect, useMemo, useRef, useState } from "react";
import { getReplay, getToken, health, listLoops, setToken, startLoop } from "./api";
import { Footer, Header, Landing, Rings, type Route } from "./chrome";
import { Docs } from "./docs";
import { ContainmentLab, DualChart, Feed, Heldout, Kpis, Patches } from "./components";
import { reduce } from "./reduce";
import { SAMPLE_ID } from "./sample";
import type { Model } from "./types";
import { useEvents, type Source } from "./useEvents";

type LoopRow = { id: string; created: number; status: string };

function useRoute(): [Route, (r: Route, section?: string) => void] {
  const read = (): Route => (window.location.hash.startsWith("#/dashboard") ? "dashboard" : window.location.hash.startsWith("#/docs") ? "docs" : "home");
  const [route, setRoute] = useState<Route>(read);
  useEffect(() => {
    const f = () => setRoute(read());
    window.addEventListener("hashchange", f);
    return () => window.removeEventListener("hashchange", f);
  }, []);
  const go = (r: Route, section?: string) => {
    window.location.hash = r === "dashboard" ? "#/dashboard" : r === "docs" ? "#/docs" : "#/";
    setRoute(r);
    window.setTimeout(() => {
      if (section) document.getElementById(section)?.scrollIntoView({ behavior: "smooth" });
      else window.scrollTo({ top: 0 });
    }, 60);
  };
  return [route, go];
}

const STAGES: [string, string][] = [["Attack", "LLM hides an injection"], ["Detect", "state-diff verifier"], ["Patch", "narrowing only"], ["Verify", "utility gate + regression"], ["Generalize", "held-out families"]];

function stageIndex(m: Model): number {
  if (m.status === "idle") return -1;
  const last = m.feed[m.feed.length - 1];
  if (!last) return 0;
  if (last.kind === "done") return 4;
  if (last.kind === "patch") return last.title.toLowerCase().includes("propos") ? 2 : 3;
  if (last.kind === "tool" || last.kind === "verdict") return 1;
  return 0;
}

function Stepper({ label, value, min, max, set }: { label: string; value: number; min: number; max: number; set: (n: number) => void }) {
  return (
    <div className="field">
      <span className="lbl">{label}</span>
      <div className="stepper">
        <button aria-label={`Fewer ${label.toLowerCase()}`} onClick={() => set(Math.max(min, value - 1))}>−</button>
        <b>{value}</b>
        <button aria-label={`More ${label.toLowerCase()}`} onClick={() => set(Math.min(max, value + 1))}>+</button>
      </div>
    </div>
  );
}

function Option({ title, hint, checked, set }: { title: string; hint: string; checked: boolean; set: (b: boolean) => void }) {
  return (
    <label className="opt">
      <span><b>{title}</b><small>{hint}</small></span>
      <input className="tg" type="checkbox" role="switch" checked={checked} onChange={(e) => set(e.target.checked)} />
    </label>
  );
}

function Dashboard({ visible }: { visible: boolean }) {
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
  const [hp, setHp] = useState<{ tool_mode: string; busy: boolean; runtime: string; models?: { attacker_patcher: string; worker: string } } | null>(null);
  const [down, setDown] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [cfgOpen, setCfgOpen] = useState(true);
  const auto = useRef(false);

  const { events, error } = useEvents(source);
  const model = useMemo(() => reduce(events), [events]);
  const refresh = () => listLoops().then((l) => { setLoops(l); setLoaded(true); }).catch(() => undefined);

  const ping = () => health()
    .then((h) => { setDown((was) => { if (was) refresh(); return false; }); setHp({ tool_mode: h.tool_mode, busy: h.busy, runtime: String(h.sandbox?.runtime ?? "docker"), models: h.models }); })
    .catch(() => setDown(true));
  useEffect(() => {
    refresh();
    ping();
    const t = window.setInterval(ping, 10000);
    return () => window.clearInterval(t);
  }, []);
  useEffect(() => { if (model.status === "done" || model.status === "failed") refresh(); }, [model.status]);

  // Show data right away: open the newest finished run once, so the dashboard is never blank.
  useEffect(() => {
    if (!loaded || auto.current) return;
    auto.current = true;
    // A loop already running on the server (started before this page was opened): follow it live.
    const live = loops.filter((l) => l.status === "running" || l.status === "pending").sort((a, b) => b.created - a.created)[0];
    if (live && !source) { setPick(live.id); setSource({ mode: "live", loopId: live.id, speed: 1 }); return; }
    const done = loops.filter((l) => l.status === "done").sort((a, b) => b.created - a.created).slice(0, 5);
    if (!done.length || source) return;
    (async () => {
      // Prefer the newest run that actually did something (baseline utility above 0); else the newest one.
      let pickId = done[0].id;
      for (const l of done) {
        try {
          const ev = await getReplay(l.id);
          const base = ev.find((e) => e.type === "metrics" && e.data?.round === 0);
          if (base && base.data.utility?.passed > 0) { pickId = l.id; break; }
        } catch { /* try the next one */ }
      }
      setPick(pickId); setSource({ mode: "replay", loopId: pickId, speed: 1000 });
    })();
  }, [loaded, loops, source]);

  const isSample = source?.loopId === SAMPLE_ID;
  const loadSample = () => { setSource({ mode: "replay", loopId: SAMPLE_ID, speed: 1000 }); };

  async function start() {
    setErr(""); setToken(token);
    try {
      const { loop_id } = await startLoop({ rounds, attacks_per_round: per, use_fixed_attacks: fixed, template_patcher_only: template });
      setSource({ mode: "live", loopId: loop_id, speed: 1 });
    } catch (e) { setErr(String(e instanceof Error ? e.message : e)); }
  }

  const running = model.status === "running" && source?.mode === "live";
  const canEval = model.status === "done" && source !== null && !isSample;
  const withAsr = model.metrics.filter((r) => r.asr);
  const first = withAsr[0]?.asr, lastAsr = withAsr[withAsr.length - 1]?.asr;
  const pct = (r?: { rate: number } | null) => (r ? `${Math.round(r.rate * 100)}%` : "–");
  const stage = stageIndex(model);
  const progress = model.status === "done" ? 100 : model.status === "running" ? Math.min(95, Math.round((model.round / Math.max(1, rounds)) * 100)) : 0;

  const viewing = !source ? "nothing loaded" : isSample ? "sample data (illustrative)" : `${source.mode === "live" ? "live run" : "saved run"} ${source.loopId}`;

  return (
    <div hidden={!visible}>
      <div className="wrap app">
        <div className="page-head" id="runs">
          <div>
            <div className="eyebrow">DASHBOARD</div>
            <h1>Blast radius, round by round</h1>
            <p className="muted">Viewing: <b className="viewing">{viewing}</b></p>
          </div>
          <div className="page-actions">
            <button className="btn" onClick={() => setCfgOpen((o) => !o)} aria-expanded={cfgOpen}>{cfgOpen ? "Hide run settings" : "Run settings"}</button>
            {!source && <button className="btn" onClick={loadSample}>Preview sample</button>}
            <button className="btn primary" disabled={running || down} onClick={start}>{running ? "Running…" : "Start loop"}</button>
          </div>
        </div>

        {model.status === "failed" && (
          <div className="banner" role="alert">
            <span><b>Run failed.</b> {model.feed[model.feed.length - 1]?.title.replace(/^Failed: /, "")} If this mentions the LLM, check <code>VULTR_API_KEY</code> and <code>MODEL_NAME</code> in <code>.env</code> on the server, then run <code>docker compose up -d</code>.</span>
          </div>
        )}
        {!isSample && model.status === "done" && model.metrics[0] && model.metrics[0].utility.total > 0 && model.metrics[0].utility.passed === 0 && (
          <div className="banner" role="alert">
            <span><b>This run is not meaningful.</b> The agent completed 0 of {model.metrics[0].utility.total} normal tasks, so 0% attack success only means nothing worked. This usually means the LLM call failed (wrong key, model name or no credit). Fix <code>.env</code> and start a new run.</span>
          </div>
        )}
        {isSample && (
          <div className="banner sample" role="note">
            <span><b>Sample data.</b> These numbers are illustrative and were not measured. They only show what a finished run looks like. Run a loop, or open a saved run, to see real results.</span>
            <button className="btn" onClick={() => setSource(null)}>Clear</button>
          </div>
        )}
        {!source && loaded && loops.length === 0 && !down && (
          <div className="empty" role="note">
            <b>No runs yet.</b>
            <span className="muted">Start a loop (needs the admin token if one is set) and results appear here live. To see the layout first, use <i>Preview sample</i>.</span>
          </div>
        )}

        <div className="strip">
          <span>backend <b className={down ? "" : "good"}>{down ? "unreachable" : "ok"}</b></span>
          <span>tool mode <b>{hp?.tool_mode ?? "–"}</b></span>
          <span>sandbox <b>hardened Docker ({hp?.runtime ?? "–"})</b></span>
          <span>inference <b>Vultr Serverless</b></span>
          {hp?.models && <span>agent model <b>{hp.models.worker}</b></span>}
          {hp?.models && <span>attacker + patcher <b>{hp.models.attacker_patcher}</b></span>}
          <span>judge <b className="good">deterministic code</b></span>
          {hp?.busy && <span><b>a loop is running</b></span>}
        </div>

        {down && (
          <div className="banner" role="alert">
            <span><b>Backend unreachable.</b> Start the API (<code>uvicorn app.main:app</code> on :8000, or <code>docker compose up -d</code>). This page keeps retrying.</span>
            <button className="btn" onClick={ping}>Retry now</button>
          </div>
        )}

        <section className="hero">
          <div className="hero-rings">
            <Rings m={model} />
            <div className="hero-copy">
              <div className="eyebrow">BLAST RADIUS</div>
              <div className="hero-num">{pct(first)} <span className="to">→</span> <span className="end">{pct(lastAsr)}</span></div>
              <p className="muted">Each ring is the share of attacks that still work after a round of patching. Utility is tracked next to it, so a smaller ring is not just a locked-down agent.</p>
            </div>
          </div>
          <Kpis m={model} />
        </section>

        <section className="stages" aria-label="Loop stages">
          {STAGES.map(([n, sub], i) => (
            <div key={n} className={`stage ${i === stage ? "on" : ""}`}><span className="n">0{i + 1}</span><span className="nm">{n}</span><span className="sb">{sub}</span></div>
          ))}
        </section>

        <section className="card panel" hidden={!cfgOpen}>
          <div className="cfg">
            <div className="card-h"><h3>Run configuration</h3></div>
            <div className="row">
              <Stepper label="Rounds" value={rounds} min={1} max={8} set={setRounds} />
              <Stepper label="Attacks per round" value={per} min={1} max={20} set={setPer} />
              <div className="field">
                <span className="lbl">Replay speed</span>
                <div className="seg" role="group" aria-label="Replay speed">
                  {[1, 2, 4, 8, 16].map((s) => <button key={s} className={speed === s ? "on" : ""} onClick={() => setSpeed(s)}>{s}×</button>)}
                </div>
              </div>
            </div>
            <div className="opts">
              <Option title="Fixed payloads" hint="Use stored attacks, skip the attacker LLM" checked={fixed} set={setFixed} />
              <Option title="Template patcher only" hint="No LLM patcher, rule-based patches" checked={template} set={setTemplate} />
            </div>
            <label className="field">
              <span className="lbl">Admin token</span>
              <input className="token" type="password" value={token} placeholder="Required to start a run" onChange={(e) => { setTok(e.target.value); setToken(e.target.value); }} />
              <span className="muted small">Viewers can watch and replay without it. Only you can start new runs.</span>
            </label>
          </div>
          <div className="run">
            <div className="card-h"><h3>Run</h3></div>
            <div>
              <div className="row" style={{ justifyContent: "space-between", margin: 0, gap: 8 }}><span className="muted small">{model.status === "idle" ? "idle" : `round ${model.round} of ${rounds}`}</span><span className="muted small">policy v{model.policyVersion}</span></div>
              <div className="progress" role="progressbar" aria-valuenow={progress} aria-valuemin={0} aria-valuemax={100} aria-label="Loop progress"><div style={{ width: `${progress}%` }} /></div>
            </div>
            <button className="btn primary big" disabled={running || down} onClick={start}>{running ? "Running…" : "Start loop"}</button>
            {(err || error) && <p className="err small">{err || error}</p>}
            <div className="field" style={{ borderTop: "1px solid var(--line)", paddingTop: 14 }}>
              <span className="lbl">Past runs</span>
              <select value={pick} onChange={(e) => setPick(e.target.value)} onFocus={refresh}>
                <option value="">Select a run…</option>
                {loops.map((l) => <option key={l.id} value={l.id}>{l.id} · {l.status} · {new Date(l.created * 1000).toLocaleTimeString()}</option>)}
              </select>
              <div className="run-pair">
                <button className="btn" disabled={!pick} onClick={() => setSource({ mode: "replay", loopId: pick, speed })}>Replay</button>
                <button className="btn" disabled={!pick} onClick={() => setSource({ mode: "live", loopId: pick, speed: 1 })}>Open</button>
              </div>
            </div>
          </div>
        </section>

        <div className="grid">
          <div className="col">
            <DualChart m={model} />
            <Heldout loopId={source?.loopId ?? null} version={model.policyVersion} disabled={!canEval} fixed={fixed} />
            <div id="policy"><Patches items={model.patches} /></div>
          </div>
          <Feed items={model.feed} />
        </div>
        <div id="lab"><ContainmentLab /></div>
      </div>
    </div>
  );
}

export default function App() {
  const [route, go] = useRoute();
  const right = route === "home"
    ? (<><span className="pill live"><span className="dot" />live on Vultr</span><button className="btn primary" onClick={() => go("dashboard")}>Open dashboard</button></>)
    : route === "docs"
      ? (<button className="btn primary" onClick={() => go("dashboard")}>Open dashboard</button>)
      : null;
  return (
    <>
      <Header route={route} go={go} right={right} />
      {route === "home" && <Landing go={go} />}
      {route === "docs" && <Docs go={go} />}
      <Dashboard visible={route === "dashboard"} />
      {route === "dashboard" && <div className="wrap" style={{ paddingBottom: 56 }}><Footer /></div>}
    </>
  );
}
