"""FastAPI surface for typed gateway decisions."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict

from .factory import build_local_lab
from .lab import nominal_state
from .models import ActionProposal, Decision, SystemState


class DecisionRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    proposal: ActionProposal
    state: SystemState


app = FastAPI(title="Aegis-OT", version="0.1.0")
_lab = build_local_lab(datetime.now(UTC))


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "synthetic-local"}


@app.post("/v1/decisions", response_model=Decision)
def decide(request: DecisionRequest) -> Decision:
    return _lab.gateway.decide(request.proposal, request.state)


@app.get("/v1/state", response_model=SystemState)
def state() -> SystemState:
    return nominal_state()
