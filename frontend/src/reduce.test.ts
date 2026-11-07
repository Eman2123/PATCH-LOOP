import { describe, expect, it } from "vitest";
import { chartRows, reduce } from "./reduce";
import type { LoopEvent } from "./types";

const ev = (seq: number, type: string, data: any): LoopEvent => ({ loop_id: "x", seq, type, data });

describe("reduce", () => {
  const events = [
    ev(0, "metrics", { round: 0, policy_version: 0, utility: { passed: 10, total: 10 }, asr: null }),
    ev(1, "round_start", { round: 1, policy_version: 0 }),
    ev(2, "attack", { family: "F1", payload: "p", source: "fixed", carrier: "file" }),
    ev(3, "tool_call", { tool: "fetch_url", args: { url: "u" }, allowed: true, rule: null, reason: "ok" }),
    ev(4, "verdict", { breached: true, damage: 8, breaches: ["canary_hit"], contained: [], why: "" }),
    ev(5, "patch_proposed", { round: 1, family: "F1", source: "template", attempts: 0, version: 1, patch: { op: "ADD_DENY" } }),
    ev(6, "patch_accepted", { round: 1, family: "F1", version: 1, patch: {}, utility: { passed: 10, total: 10 } }),
    ev(7, "metrics", { round: 1, policy_version: 1, asr: { k: 1, n: 1, rate: 1, lo: 0.2, hi: 1 }, utility: { passed: 10, total: 10, baseline: 10 } }),
    ev(8, "done", { status: "done", final_policy_version: 1 }),
  ];

  it("builds the model from events", () => {
    const m = reduce(events);
    expect(m.status).toBe("done");
    expect(m.policyVersion).toBe(1);
    expect(m.patches[0].status).toBe("accepted");
    expect(m.feed.map((f) => f.kind)).toContain("verdict");
    expect(m.feed.find((f) => f.kind === "verdict")?.tone).toBe("bad");
  });

  it("is a prefix function (replay shows partial state)", () => {
    const m = reduce(events.slice(0, 5));
    expect(m.status).toBe("running");
    expect(m.patches).toHaveLength(0);
  });

  it("marks rejected patches with the reason", () => {
    const m = reduce([
      ev(0, "patch_proposed", { round: 2, family: "F2", source: "llm", version: 3, patch: {} }),
      ev(1, "patch_rejected", { round: 2, family: "F2", reason: "utility gate: 7/10" }),
    ]);
    expect(m.patches[0]).toMatchObject({ status: "rejected", reason: "utility gate: 7/10" });
  });

  it("chart rows are percentages with a CI band", () => {
    const rows = chartRows(reduce(events).metrics);
    expect(rows[0]).toMatchObject({ round: 0, asr: null, utility: 100 });
    expect(rows[1]).toMatchObject({ round: 1, asr: 100, utility: 100, band: [20, 100] });
  });
});
