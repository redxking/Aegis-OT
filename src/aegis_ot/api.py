"""Separated public-evidence and local control-research API surfaces."""

from __future__ import annotations

from datetime import UTC, datetime
from importlib.resources import files
from threading import Lock
from typing import Final

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import BaseModel, ConfigDict

from .factory import LocalLab, build_local_lab
from .lab import nominal_state
from .models import ActionProposal, Decision, SystemState
from .public_demo import PublicDemoEvidence, load_public_demo_evidence


class DecisionRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    proposal: ActionProposal
    state: SystemState


DEMO_SECURITY_HEADERS: Final[dict[str, str]] = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; "
        "form-action 'none'; frame-ancestors 'none'; img-src 'self' data:; "
        "object-src 'none'; script-src 'self'; style-src 'self'"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}
DEMO_ASSET_TYPES: Final[dict[str, str]] = {
    "app.css": "text/css; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
}


public_app = FastAPI(
    title="Aegis-OT Public Evidence Demonstration",
    description="Read-only presentation of retained synthetic-local research evidence.",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
)
control_app = FastAPI(
    title="Aegis-OT Local Control Research API",
    description=(
        "Mutable synthetic-local decision surface for authorized development testing only; "
        "it is not mounted by the public demonstration container."
    ),
    version="0.1.0",
)
# The container and the documented default launch target expose only the public app.
app = public_app
_lab: LocalLab | None = None
_control_lab_lock = Lock()


def _local_control_lab() -> LocalLab:
    """Construct mutable research state only when the local control app is used."""

    global _lab  # noqa: PLW0603 - process-local lazy control state
    if _lab is None:
        with _control_lab_lock:
            if _lab is None:
                _lab = build_local_lab(datetime.now(UTC))
    return _lab


def _demo_asset(name: str) -> str:
    if name not in {"index.html", *DEMO_ASSET_TYPES}:
        raise ValueError("unregistered public-demo asset")
    return files("aegis_ot").joinpath("web_demo", name).read_text(encoding="utf-8")


@public_app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/demo", status_code=307, headers=DEMO_SECURITY_HEADERS)


@public_app.get("/demo", response_class=HTMLResponse, include_in_schema=False)
def public_demo() -> HTMLResponse:
    return HTMLResponse(_demo_asset("index.html"), headers=DEMO_SECURITY_HEADERS)


@public_app.get("/demo/{asset_name}", include_in_schema=False)
def public_demo_asset(asset_name: str) -> Response:
    media_type = DEMO_ASSET_TYPES.get(asset_name)
    if media_type is None:
        return Response(status_code=404, headers=DEMO_SECURITY_HEADERS)
    return Response(
        content=_demo_asset(asset_name),
        media_type=media_type,
        headers=DEMO_SECURITY_HEADERS,
    )


@public_app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "synthetic-local", "public_demo": "/demo"}


@public_app.get("/v1/demo/evidence", response_model=PublicDemoEvidence)
def public_demo_evidence() -> PublicDemoEvidence:
    """Return a generated, read-only summary of committed M2 and M3 evidence."""

    return load_public_demo_evidence()


@control_app.post("/v1/decisions", response_model=Decision)
def decide(request: DecisionRequest) -> Decision:
    return _local_control_lab().gateway.decide(request.proposal, request.state)


@control_app.get("/v1/state", response_model=SystemState)
def state() -> SystemState:
    return nominal_state()
