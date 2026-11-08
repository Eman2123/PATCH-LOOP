"""FastAPI app. Endpoints follow contracts/api.md. One loop/eval runs at a time (protects LLM credits and Docker)."""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from .containment import ATTACKS, BY_ID, LabResult, kernel_view, lab_sandbox, run_lab_attack
from .db import Store
from .evaluation import run_heldout
from .llm import LLM
from .loop import LoopConfig, LoopRunner
from .policy import Policy
from .sandbox import default_sandbox, make_python_runner
from .schemas import HeldoutRequest, LoopEvent, LoopStartRequest, LoopState


@dataclass
class Deps:
    """Injection points so tests run without network or Docker."""
    make_llm: Callable[[], Any] = LLM.from_env
    make_worker_llm: Optional[Callable[[], Any]] = None  # None: use WORKER_MODEL_NAME from the env if set
    suite_llm_for: Optional[Callable[[Any], Any]] = None
    python_runner: Optional[Callable[[str], dict]] = None
    use_default_sandbox: bool = True
    lab_sandbox: Callable[[], Any] = lab_sandbox

    def runner(self) -> Optional[Callable[[str], dict]]:
        if self.python_runner is not None or not self.use_default_sandbox:
            return self.python_runner
        sb = default_sandbox()
        return make_python_runner(sb) if sb.status().get("docker") else None


@dataclass
class Busy:
    lock: threading.Lock = field(default_factory=threading.Lock)
    what: str = ""


def create_app(deps: Optional[Deps] = None, db_path: Optional[str] = None, results_dir: Optional[str] = None) -> FastAPI:
    app = FastAPI(title="PATCH LOOP", version="0.2.0")
    deps = deps or Deps()
    store = Store(db_path or os.environ.get("PATCHLOOP_DB", "data/patchloop.db"))
    results = results_dir if results_dir is not None else os.environ.get("RESULTS_DIR", "../results")
    busy = Busy()
    tool_mode = os.environ.get("TOOL_MODE", "native")
    admin_token = os.environ.get("ADMIN_TOKEN", "")
    app.state.store, app.state.deps = store, deps
    model_name = os.environ.get("MODEL_NAME", "glm-5.3")
    worker_name = os.environ.get("WORKER_MODEL_NAME", "") or model_name
    if deps.make_worker_llm is None and os.environ.get("WORKER_MODEL_NAME"):
        deps.make_worker_llm = lambda: LLM.from_env(model_env="WORKER_MODEL_NAME")

    def worker_llm() -> Any:
        return deps.make_worker_llm() if deps.make_worker_llm else None

    app.add_middleware(CORSMiddleware, allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
                       allow_methods=["GET", "POST"], allow_headers=["*"])

    def require_admin(x_admin_token: str = Header(default="")) -> None:
        if admin_token and x_admin_token != admin_token:
            raise HTTPException(401, "missing or wrong X-Admin-Token")

    def acquire(what: str) -> None:
        if not busy.lock.acquire(blocking=False):
            raise HTTPException(409, f"busy: {busy.what} is still running")
        busy.what = what

    # ---------- health ----------
    @app.get("/health")
    def health() -> dict:
        return {"ok": True, "sandbox": default_sandbox().status(), "busy": busy.lock.locked(), "tool_mode": tool_mode,
                "models": {"attacker_patcher": model_name, "worker": worker_name}}

    # ---------- loop ----------
    @app.post("/loop/start", dependencies=[Depends(require_admin)])
    def loop_start(req: LoopStartRequest) -> dict:
        try:
            llm = deps.make_llm()
        except Exception as e:  # noqa: BLE001 - no key etc.
            raise HTTPException(503, f"LLM not available: {e}")
        acquire("loop")
        cfg = LoopConfig(rounds=req.rounds, attacks_per_round=req.attacks_per_round, families=list(req.families),
                         tool_mode=tool_mode, use_fixed_attacks=req.use_fixed_attacks,
                         template_patcher_only=req.template_patcher_only)
        runner = LoopRunner(llm, deps.runner(), deps.suite_llm_for, results_dir=results, worker_llm=worker_llm())
        store.create_loop(runner.loop_id, cfg.model_dump(), runner.state.model_dump())

        def sink(ev: LoopEvent) -> None:
            store.add_event(ev.loop_id, ev.seq, ev.type, ev.data)
            store.save_state(ev.loop_id, runner.state.model_dump())
            for v, p in list(runner.policies.items()):
                store.save_policy(ev.loop_id, v, p.model_dump())

        runner.sink = sink

        def work() -> None:
            try:
                runner.state.status = "running"
                store.save_state(runner.loop_id, runner.state.model_dump())  # visible as running at once, not after the first event
                runner.run(cfg)
            except Exception:  # noqa: BLE001 - run() already reports; this is the last resort
                runner.state.status = "failed"
            finally:
                store.save_state(runner.loop_id, runner.state.model_dump())
                for v, p in runner.policies.items():
                    store.save_policy(runner.loop_id, v, p.model_dump())
                busy.lock.release()

        threading.Thread(target=work, daemon=True, name=f"loop-{runner.loop_id}").start()
        return {"loop_id": runner.loop_id}

    @app.get("/loops")
    def loops() -> list[dict]:
        return store.list_loops()

    @app.get("/loop/{loop_id}", response_model=LoopState)
    def loop_state(loop_id: str) -> LoopState:
        row = store.get_loop(loop_id)
        if not row:
            raise HTTPException(404, "unknown loop")
        return LoopState(**{**row["state"], "status": row["status"]})

    @app.get("/loop/{loop_id}/events")
    def loop_events(loop_id: str, from_seq: int = Query(0, ge=0)) -> StreamingResponse:
        if not store.get_loop(loop_id):
            raise HTTPException(404, "unknown loop")

        def stream() -> Iterator[str]:
            last, idle = from_seq - 1, 0
            while True:
                rows = store.events(loop_id, last)
                for r in rows:
                    last = r["seq"]
                    yield f"id: {r['seq']}\ndata: {json.dumps(r)}\n\n"
                loop = store.get_loop(loop_id)
                if loop and loop["status"] in ("done", "failed") and not rows:
                    break
                idle = 0 if rows else idle + 1
                if idle and idle % 50 == 0:
                    yield ": keepalive\n\n"
                time.sleep(0.25)

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.get("/replay/{loop_id}", response_model=list[LoopEvent])
    def replay(loop_id: str) -> list[dict]:
        if not store.get_loop(loop_id):
            raise HTTPException(404, "unknown loop")
        return store.events(loop_id)

    @app.get("/policy/{version}", response_model=Policy)
    def policy(version: int, loop_id: Optional[str] = None) -> Policy:
        got = store.get_policy(version, loop_id)
        if not got:
            raise HTTPException(404, "unknown policy version")
        return Policy(**got[1])

    # ---------- containment lab (fixed attacks only; clients pick an id, never send code) ----------
    lab_slots = threading.BoundedSemaphore(4)

    @app.get("/containment/attacks")
    def containment_attacks() -> list[dict]:
        return [{"id": a.id, "title": a.title, "goal": a.goal, "expect": a.expect, "code": a.code} for a in ATTACKS]

    @app.post("/containment/run/{attack_id}", response_model=LabResult)
    def containment_run(attack_id: str) -> LabResult:
        attack = BY_ID.get(attack_id)
        if attack is None:
            raise HTTPException(404, "unknown attack")
        if not lab_slots.acquire(blocking=False):
            raise HTTPException(429, "too many sandbox runs in flight, retry in a moment")
        try:
            return run_lab_attack(deps.lab_sandbox(), attack)
        finally:
            lab_slots.release()

    @app.get("/containment/kernel")
    def containment_kernel() -> dict:
        if not lab_slots.acquire(blocking=False):
            raise HTTPException(429, "too many sandbox runs in flight, retry in a moment")
        try:
            return kernel_view(deps.lab_sandbox())
        finally:
            lab_slots.release()

    # ---------- held-out eval ----------
    @app.post("/eval/heldout", dependencies=[Depends(require_admin)])
    def eval_heldout(req: HeldoutRequest) -> dict:
        got = store.get_policy(req.policy_version, req.loop_id)
        if not got:
            raise HTTPException(404, "unknown policy version (run a loop first)")
        loop_id, body = got
        try:
            llm = deps.make_llm()
        except Exception as e:  # noqa: BLE001
            raise HTTPException(503, f"LLM not available: {e}")
        wllm = worker_llm()
        acquire("eval")
        eval_id = uuid.uuid4().hex[:10]
        store.create_eval(eval_id, loop_id, req.model_dump())

        def work() -> None:
            try:
                res = run_heldout(llm, deps.runner(), Policy(**body), list(req.configs), req.n_per_family,
                                  tool_mode=tool_mode, use_fixed_attacks=req.use_fixed_attacks,
                                  suite_llm_for=deps.suite_llm_for, worker_llm=wllm)
                res.update({"eval_id": eval_id, "loop_id": loop_id, "policy_version": req.policy_version})
                store.finish_eval(eval_id, "done", res)
                os.makedirs(results, exist_ok=True)
                with open(os.path.join(results, f"eval_{eval_id}.json"), "w", encoding="utf-8") as f:
                    json.dump(res, f, indent=2)
            except Exception as e:  # noqa: BLE001
                store.finish_eval(eval_id, "failed", {"error": f"{type(e).__name__}: {e}"[:300]})
            finally:
                busy.lock.release()

        threading.Thread(target=work, daemon=True, name=f"eval-{eval_id}").start()
        return {"eval_id": eval_id}

    @app.get("/eval/{eval_id}")
    def eval_get(eval_id: str) -> dict:
        row = store.get_eval(eval_id)
        if not row:
            raise HTTPException(404, "unknown eval")
        return row

    return app


app = create_app()
