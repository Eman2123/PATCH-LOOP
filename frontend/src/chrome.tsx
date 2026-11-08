import type { ReactNode } from "react";
import type { Model } from "./types";

export type Route = "home" | "dashboard";

export function Logo({ size = 30 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" role="img" aria-label="Patch Loop logo">
      <circle cx="20" cy="20" r="12" fill="none" stroke="var(--acc)" strokeWidth="3.2" strokeLinecap="round" strokeDasharray="62 14" transform="rotate(-60 20 20)" />
      <polygon points="16.2,8.1 11.6,7.6 15,12.5" fill="var(--acc)" stroke="var(--acc)" strokeWidth="1.5" strokeLinejoin="round" />
      <circle cx="20" cy="20" r="4.5" fill="var(--bad)" />
      <rect x="27" y="27" width="6" height="6" rx="1.5" fill="var(--ok)" />
    </svg>
  );
}

const SECTIONS: [string, string][] = [["Runs", "runs"], ["Policy", "policy"], ["Containment Lab", "lab"]];

export function Header({ route, go, right }: { route: Route; go: (r: Route, section?: string) => void; right: ReactNode }) {
  return (
    <header className="site-header">
      <div className="wrap">
        <button className="brand" onClick={() => go("home")} aria-label="Patch Loop home">
          <span className="brand-tile"><Logo /></span>
          <span><span className="brand-name">PATCH LOOP</span><span className="brand-sub">BLAST RADIUS ZERO</span></span>
        </button>
        <nav className="nav" aria-label="Sections">
          <button className={route === "home" ? "on" : ""} onClick={() => go("home")}>Home</button>
          <button className={route === "dashboard" ? "on" : ""} onClick={() => go("dashboard")}>Dashboard</button>
          {SECTIONS.map(([label, id]) => <button key={id} onClick={() => go("dashboard", id)}>{label}</button>)}
          <a href="https://github.com/Eman2123/PATCH-LOOP" target="_blank" rel="noreferrer">Docs</a>
        </nav>
        <div className="hdr-right">{right}</div>
      </div>
    </header>
  );
}

export function Footer() {
  return (
    <footer className="site-footer">
      <div className="foot-top">
        <div className="foot-word" aria-hidden="true">PATCH LOOP</div>
        <p>Agents that get attacked, patch their own permissions, and prove the patch did not break the job.</p>
      </div>
      <div className="foot-cols">
        <div><b>PRODUCT</b><span>Dashboard</span><span>Runs and replay</span><span>Policy and patches</span><span>Containment Lab</span></div>
        <div><b>BUILT WITH</b><span>Vultr Cloud Compute</span><span>Vultr Serverless Inference</span><span>FastAPI, SQLite, Caddy</span><span>React, Vite, TypeScript</span></div>
        <div className="wide"><b className="w">HONEST LIMITS</b>
          <span>Results are preliminary: small N, simulated world (fake web, fake mail, canary sink).</span>
          <span>Adaptive policy refinement, not model training. Damage weights are an opinion.</span>
          <span>The verifier is deterministic code, never an LLM. The sandbox is hardened Docker, not gVisor.</span>
        </div>
      </div>
      <div className="foot-bot">
        <span>Built for lablab.ai, Vultr Agent Rush, Track 1 "Blast Radius Zero"</span>
        <span><a href="https://github.com/Eman2123/PATCH-LOOP" target="_blank" rel="noreferrer">GitHub</a> · MIT license</span>
      </div>
    </footer>
  );
}

/** Concentric rings: one per round, radius = attack success rate. Empty state shows dashed guide rings. */
export function Rings({ m, size = 300, sample = false }: { m?: Model; size?: number; sample?: boolean }) {
  const rows = sample
    ? [{ round: 0, rate: 0.8 }, { round: 1, rate: 0.6 }, { round: 2, rate: 0.4 }, { round: 3, rate: 0.2 }]
    : (m?.metrics ?? []).filter((r) => r.asr).slice(-5).map((r) => ({ round: r.round, rate: r.asr!.rate }));
  const radius = (rate: number) => 28 + rate * 120;
  const stroke = ["var(--line2)", "var(--line3)", "var(--dim)", "var(--muted)", "var(--bad)"];
  return (
    <svg width={size} height={size} viewBox="0 0 360 360" role="img" aria-label="Blast radius rings, one per round, sized by attack success rate">
      {rows.length === 0 && [148, 116, 84, 52].map((r) => <circle key={r} cx="180" cy="180" r={r} fill="none" stroke="var(--line2)" strokeWidth="1.5" strokeDasharray="4 5" />)}
      {rows.map((r, i) => {
        const last = i === rows.length - 1;
        return <circle key={i} cx="180" cy="180" r={radius(r.rate)} fill={last ? "var(--bad)" : "none"} fillOpacity={last ? 0.18 : 0} stroke={last ? "var(--bad)" : stroke[Math.min(i, 3)]} strokeWidth={last ? 2 : 1.5} strokeDasharray={last ? undefined : "4 5"} />;
      })}
      <circle cx="180" cy="180" r="5" fill="var(--text)" />
      <g fontFamily="JetBrains Mono, monospace" fontSize="11" fill="var(--muted)" textAnchor="middle">
        {rows.map((r, i) => <text key={i} x="180" y={180 - radius(r.rate) + 16} fill={i === rows.length - 1 ? "var(--bad)" : "var(--muted)"}>{r.round === 0 ? "baseline" : `r${r.round}`} {Math.round(r.rate * 100)}%</text>)}
        {rows.length === 0 && <text x="180" y="236">run a loop to draw the rings</text>}
        <text x="180" y="212" fill="var(--text)">OfficeBot</text>
      </g>
    </svg>
  );
}

export function Landing({ go }: { go: (r: Route, section?: string) => void }) {
  const steps: [string, string, string, string][] = [
    ["01", "Attack", "An attacker agent hides a prompt injection in a fake web page or file.", "var(--bad)"],
    ["02", "Detect", "A deterministic verifier compares world state before and after. It never trusts the agent's own story.", "var(--warn)"],
    ["03", "Patch", "A patcher agent proposes a policy change that can only narrow permissions.", "var(--text)"],
    ["04", "Verify", "The patch must stop the attack and cost at most one benign task.", "var(--ok)"],
    ["05", "Generalize", "Held-out attack families check that the patch did not just memorize.", "var(--acc)"],
  ];
  const head = (tag: string, title: string, sub?: string) => (
    <div className="sec-h"><div className="eyebrow">{tag}</div><h2>{title}</h2>{sub && <p>{sub}</p>}</div>
  );
  return (
    <div className="wrap land">
      <section className="land-hero">
        <div>
          <div className="tag-pill"><i />VULTR AGENT RUSH · TRACK 1</div>
          <h1>Agents that patch their own <span>blast radius.</span></h1>
          <p className="lead">Patch Loop attacks an AI agent, finds where it leaks, and tightens its permissions automatically. Every patch has to prove the agent can still do its job.</p>
          <div className="ctas">
            <button className="btn primary big" onClick={() => go("dashboard")}>Open the dashboard →</button>
            <a className="btn big" href="#how">How it works</a>
          </div>
          <div className="chips"><span>deterministic judge</span><span>narrowing-only patches</span><span>real sandbox</span></div>
        </div>
        <div>
          <div className="ring-card">
            <Rings sample size={380} />
            <div className="ring-cap">illustration: attack success shrinking round by round</div>
          </div>
        </div>
      </section>

      <section>
        <div className="tiles">
          <div className="tile"><b>7</b><span>real attacks in the sandbox</span></div>
          <div className="tile"><b>5</b><span>narrowing-only patch operations</span></div>
          <div className="tile"><b>3 + 3</b><span>training and held-out attack families</span></div>
          <div className="tile"><b>0</b><span>LLMs in the judge. It is code.</span></div>
        </div>
      </section>

      <section>
        {head("01 / PROBLEM", "Why agent security breaks down", "Companies want agents that read mail, browse the web and run code. That is also what makes them easy to abuse.")}
        <div className="cards">
          <div className="lcard"><h4>One poisoned page is enough</h4><p>A hidden instruction in a web page or file can make an agent read secrets and send them out.</p></div>
          <div className="lcard"><h4>Static allow-lists do not fit</h4><p>Too loose and the attack works. Too tight and the agent stops being useful.</p></div>
          <div className="lcard"><h4>Nobody hand-tunes forever</h4><p>Every new attack needs a new rule, a review and a regression check. Patch Loop automates that loop.</p></div>
        </div>
      </section>

      <section id="how">
        {head("02 / HOW IT WORKS", "Five steps, one loop", "The loop repeats until the policy is tight enough, and utility must hold at every step.")}
        <div className="cards">
          {steps.map(([n, name, text, color]) => (
            <div className="lcard" key={n}><div className="no" style={{ color }}>{n}</div><h4 style={{ color }}>{name}</h4><p>{text}</p></div>
          ))}
        </div>
      </section>

      <section>
        {head("03 / TWO LAYERS", "Safety at two levels")}
        <div className="cards two">
          <div className="lcard"><div className="no eyebrow">LAYER 1</div><h4>Policy gateway</h4><p>Decides what a tool call is allowed to do, before it runs.</p>
            <ul><li>Path normalization and ../ traversal</li><li>URL userinfo tricks and subdomain spoofing</li><li>Private IPs, ports and redirect re-checks</li></ul></div>
          <div className="lcard"><div className="no eyebrow">LAYER 2</div><h4>Sandbox</h4><p>Limits what code can physically do once it runs.</p>
            <ul><li>No network, all capabilities dropped</li><li>Read-only filesystem, memory and pid limits</li><li>Fresh container, destroyed after every run</li></ul></div>
        </div>
      </section>

      <section className="lcard warn">
        <div className="eyebrow" style={{ color: "var(--warn)" }}>HONEST LIMITS</div>
        <ul>
          <li>Results are preliminary: small N, simulated world with a fake web, fake mail and canary sink.</li>
          <li>This is adaptive policy refinement, not model training.</li>
          <li>The verifier is deterministic code, never an LLM. The sandbox is hardened Docker, not gVisor.</li>
        </ul>
      </section>

      <section className="cta">
        <h2>See the blast radius shrink.</h2>
        <p>Start a loop or replay a saved run, and watch attack success fall while the agent keeps working.</p>
        <button className="btn primary big" onClick={() => go("dashboard")}>Open the dashboard →</button>
      </section>
      <Footer />
    </div>
  );
}
