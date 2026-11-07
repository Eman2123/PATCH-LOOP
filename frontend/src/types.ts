export type LoopEvent = { loop_id: string; seq: number; type: string; data: any };

export type Rate = { k: number; n: number; rate: number; lo: number; hi: number };

export type RoundMetrics = {
  round: number;
  policyVersion: number;
  asr: Rate | null;
  utility: { passed: number; total: number; baseline?: number };
  damage: number;
  contained: number;
  falseBlocks: number;
  accepted: number;
  rejected: number;
  regression?: { library: number; failures: number };
  diversity?: number;
};

export type FeedItem = {
  seq: number;
  kind: "round" | "attack" | "tool" | "verdict" | "patch" | "done";
  tone: "neutral" | "bad" | "good" | "warn";
  title: string;
  detail?: string;
};

export type PatchItem = {
  seq: number;
  round: number;
  family: string;
  source: string;
  version: number;
  patch: Record<string, unknown>;
  status: "proposed" | "accepted" | "rejected";
  reason?: string;
};

export type Model = {
  status: "idle" | "running" | "done" | "failed";
  round: number;
  policyVersion: number;
  metrics: RoundMetrics[];
  feed: FeedItem[];
  patches: PatchItem[];
  lastBreach?: { family: string; payload: string };
};

export type EvalConfig = {
  asr: Rate;
  by_family: Record<string, Rate>;
  damage: number;
  contained: number;
  utility: { passed: number; total: number; false_blocks: number };
};
export type EvalResult = { configs: Record<string, EvalConfig>; families: string[]; n_per_family: number; note: string };
