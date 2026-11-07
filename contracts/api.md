# API contracts (v1)

Schemas live in `backend/app/schemas.py`. Change them only via PR with a note to everyone.
One loop or eval runs at a time; a second start returns **409**. If `ADMIN_TOKEN` is set, POSTs need header `X-Admin-Token`.

| Method | Path | Body / Notes | Response |
|---|---|---|---|
| GET | /health | sandbox status, busy flag, tool_mode | {ok, sandbox, busy, tool_mode} |
| POST | /loop/start | LoopStartRequest `{rounds 1-8, attacks_per_round 1-20, families F1-F3, use_fixed_attacks, template_patcher_only}` | {"loop_id": str} (503 if no LLM key, 409 if busy) |
| GET | /loops | recent loops | [{id, created, status}] |
| GET | /loop/{id} | - | LoopState |
| GET | /loop/{id}/events?from_seq=0 | SSE. Every message is `data: <LoopEvent JSON>`; replays history, then live, then closes after `done` | text/event-stream |
| GET | /replay/{id} | full stored history | list[LoopEvent] |
| GET | /policy/{v}?loop_id= | loop_id optional (default: latest loop with that version) | Policy |
| POST | /eval/heldout | HeldoutRequest `{policy_version, loop_id?, configs, n_per_family 1-30, use_fixed_attacks}` | {"eval_id": str} |
| GET | /eval/{eval_id} | poll until status done/failed | {id, loop_id, status, request, result} |

## LoopEvent.type and data
- `metrics` (round 0 = baseline): `{round, policy_version, utility{passed,total,baseline}, asr{k,n,rate,lo,hi}, damage, contained, false_blocks, patches_accepted, patches_rejected, regression{library,failures}, attacker_diversity}`
- `round_start {round, policy_version}` / `round_end {round, accepted, rejected}`
- `attack {round,index,family,carrier,payload,source}` -> `tool_call {tool,args,allowed,rule,reason}`* -> `verdict {breached,damage,breaches,contained,why}`
- `patch_proposed {family,source,attempts,version,patch}` -> `patch_accepted {version,patch,utility}` or `patch_rejected {reason}`
- `done {status, final_policy_version | error}`

## Eval result
`result.configs.{none|prompt_guardrail|static|patched}` = `{asr{k,n,rate,lo,hi}, by_family{H1..H3}, damage, contained, utility{passed,total,false_blocks}, policy_version}`
Results are preliminary, small N. `static` is a generic hand-written policy fixed before any attack.
