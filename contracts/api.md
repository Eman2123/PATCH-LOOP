# API contracts (frozen v0)

| Method | Path | Body / Notes | Response |
|---|---|---|---|
| POST | /loop/start | LoopStartRequest | {"loop_id": str} |
| GET | /loop/{id}/events | SSE stream of LoopEvent | text/event-stream |
| GET | /loop/{id} | - | LoopState |
| POST | /eval/heldout | HeldoutRequest | {"eval_id": str} |
| GET | /policy/{v} | - | Policy |
| GET | /replay/{id} | - | list[LoopEvent] |

Schemas live in backend/app/schemas.py. Change them only via PR with a note to everyone.
