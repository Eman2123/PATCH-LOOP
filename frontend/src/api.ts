import type { EvalResult } from "./types";

const tokenKey = "patchloop_admin_token";
export const getToken = () => sessionStorage.getItem(tokenKey) ?? "";
export const setToken = (t: string) => sessionStorage.setItem(tokenKey, t);

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const t = getToken();
  if (t) headers["X-Admin-Token"] = t;
  const r = await fetch(path, { ...init, headers });
  if (!r.ok) {
    let msg = r.statusText;
    try { msg = (await r.json()).detail ?? msg; } catch { /* not json */ }
    throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  return r.json() as Promise<T>;
}

export type StartOpts = { rounds: number; attacks_per_round: number; use_fixed_attacks: boolean; template_patcher_only: boolean };
export const startLoop = (o: StartOpts) => call<{ loop_id: string }>("/loop/start", { method: "POST", body: JSON.stringify(o) });
export const listLoops = () => call<{ id: string; created: number; status: string }[]>("/loops");
export const getReplay = (id: string) => call<import("./types").LoopEvent[]>(`/replay/${id}`);
export const getPolicy = (v: number, loopId: string) => call<Record<string, unknown>>(`/policy/${v}?loop_id=${loopId}`);
export const startEval = (policy_version: number, loop_id: string, n_per_family: number, use_fixed_attacks: boolean) =>
  call<{ eval_id: string }>("/eval/heldout", { method: "POST", body: JSON.stringify({ policy_version, loop_id, n_per_family, use_fixed_attacks }) });
export const getEval = (id: string) => call<{ status: string; result: EvalResult | null }>(`/eval/${id}`);
export const health = () => call<{ ok: boolean; busy: boolean; tool_mode: string; sandbox: Record<string, unknown> }>("/health");
