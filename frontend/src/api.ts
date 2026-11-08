import type { EvalResult, LoopEvent } from "./types";

const tokenKey = "patchloop_admin_token";
export const getToken = () => { try { return sessionStorage.getItem(tokenKey) ?? ""; } catch { return ""; } };
export const setToken = (t: string) => { try { sessionStorage.setItem(tokenKey, t); } catch { /* storage blocked */ } };

/** Same-origin by default (Caddy in prod, Vite proxy in dev). Set VITE_API_BASE only if the API lives on another origin. */
const BASE = (((import.meta as unknown as { env?: Record<string, string> }).env?.VITE_API_BASE) ?? "").replace(/\/+$/, "");
export const apiUrl = (path: string) => `${BASE}${path}`;

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {};
  if (init?.body) headers["Content-Type"] = "application/json";
  const t = getToken();
  if (t) headers["X-Admin-Token"] = t;
  let r: Response;
  try {
    r = await fetch(apiUrl(path), { ...init, headers });
  } catch {
    throw new Error("Backend unreachable. Is the API running?");
  }
  if (!r.ok) {
    let msg: unknown = r.statusText || `HTTP ${r.status}`;
    try { msg = (await r.json()).detail ?? msg; } catch { /* not json */ }
    throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  return r.json() as Promise<T>;
}

export type StartOpts = { rounds: number; attacks_per_round: number; use_fixed_attacks: boolean; template_patcher_only: boolean };
export const startLoop = (o: StartOpts) => call<{ loop_id: string }>("/loop/start", { method: "POST", body: JSON.stringify(o) });
export const listLoops = () => call<{ id: string; created: number; status: string }[]>("/loops");
export const getReplay = (id: string) => call<LoopEvent[]>(`/replay/${id}`);
export const getPolicy = (v: number, loopId: string) => call<Record<string, unknown>>(`/policy/${v}?loop_id=${loopId}`);
export const startEval = (policy_version: number, loop_id: string, n_per_family: number, use_fixed_attacks: boolean) =>
  call<{ eval_id: string }>("/eval/heldout", { method: "POST", body: JSON.stringify({ policy_version, loop_id, n_per_family, use_fixed_attacks }) });
export const getEval = (id: string) => call<{ status: string; result: (EvalResult & { error?: string }) | null }>(`/eval/${id}`);
export const health = () => call<{ ok: boolean; busy: boolean; tool_mode: string; sandbox: Record<string, unknown>; models?: { attacker_patcher: string; worker: string } }>("/health");

export type LabAttackInfo = { id: string; title: string; goal: string; expect: string; code: string };
export type LabResult = { id: string; title: string; status: "contained" | "escaped" | "inconclusive" | "unavailable"; evidence: string; exit_code: number; duration_s: number; runtime: string; timeout_s: number };
export const labAttacks = () => call<LabAttackInfo[]>("/containment/attacks");
export const labRun = (id: string) => call<LabResult>(`/containment/run/${id}`, { method: "POST", body: "{}" });
export const labKernel = () => call<{ runtime: string; output: string; available: boolean }>("/containment/kernel");
