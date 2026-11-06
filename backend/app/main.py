"""FastAPI entrypoint. Only /health exists so far; loop endpoints land with loop.py (see contracts/api.md)."""
from __future__ import annotations

from fastapi import FastAPI

from .sandbox import default_sandbox

app = FastAPI(title="PATCH LOOP", version="0.1.0")


@app.get("/health")
def health() -> dict:
    return {"ok": True, "sandbox": default_sandbox().status()}
