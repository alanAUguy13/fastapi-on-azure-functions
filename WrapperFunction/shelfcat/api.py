"""
ShelfCat Truth API.

    POST /v1/truth/events   append a Rust Gate decision to the signed audit ledger
    GET  /v1/truth/events   most recent ledger records
    GET  /v1/truth/verify   recompute the whole hash chain (+ signatures)
    GET  /health            liveness

Writes require the `X-ShelfCat-Gate-Key` header to match SHELFCAT_GATE_API_KEY.
Only events with source="rust_gate" and validated=true are accepted.
"""

from __future__ import annotations

import hmac
import os
import threading
from functools import lru_cache
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, status

from .invariant import EnforcementInvariant, EnforcementViolation
from .ledger import AuditLedger
from .telemetry import ledger_verifications, tracer, truth_decisions

router = APIRouter()
_append_lock = threading.Lock()


@lru_cache(maxsize=1)
def get_ledger() -> AuditLedger:
    signing_key = None
    seed_hex = os.getenv("SHELFCAT_AUDIT_SIGNING_KEY")
    if seed_hex:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        signing_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex.strip()))
    # Default is ephemeral instance storage; point at durable/WORM-backed storage in production.
    path = os.getenv("SHELFCAT_LEDGER_PATH") or "/tmp/shelfcat/truth-ledger.jsonl"
    return AuditLedger(path, signing_key=signing_key)


def _require_gate_key(provided: str | None) -> None:
    expected = os.getenv("SHELFCAT_GATE_API_KEY")
    if not expected:
        truth_decisions.add(1, {"outcome": "unconfigured"})
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "truth writes disabled: SHELFCAT_GATE_API_KEY not set")
    if not provided or not hmac.compare_digest(provided.encode(), expected.encode()):
        truth_decisions.add(1, {"outcome": "unauthorized"})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid gate key")


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "shelfcat-truth-api", "rule": EnforcementInvariant.RULE}


@router.post("/v1/truth/events", status_code=status.HTTP_201_CREATED)
def append_truth_event(
    event: dict[str, Any],
    x_shelfcat_gate_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_gate_key(x_shelfcat_gate_key)
    with tracer.start_as_current_span("shelfcat.truth.append") as span:
        span.set_attribute("shelfcat.source", str(event.get("source")))
        span.set_attribute("shelfcat.store_id", str(event.get("store_id")))
        try:
            with _append_lock:
                record = get_ledger().append_truth_event(event)
        except EnforcementViolation as exc:
            truth_decisions.add(1, {"outcome": "blocked"})
            span.set_attribute("shelfcat.outcome", "blocked")
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
        truth_decisions.add(1, {"outcome": "accepted"})
        span.set_attribute("shelfcat.outcome", "accepted")
        span.set_attribute("shelfcat.ledger_sequence", record.sequence)
        return {
            "status": "accepted",
            "ledger_sequence": record.sequence,
            "event_hash": record.event_hash,
            "prev_hash": record.prev_hash,
            "signed": record.signature is not None,
        }


@router.get("/v1/truth/events")
def recent_events(limit: int = Query(default=50, ge=1, le=500)) -> dict[str, Any]:
    records = get_ledger()._records()
    return {"count": len(records), "records": records[-limit:]}


@router.get("/v1/truth/verify")
def verify_ledger() -> dict[str, Any]:
    ledger = get_ledger()
    with tracer.start_as_current_span("shelfcat.ledger.verify"):
        trusted = ledger.signing_key.public_key() if ledger.signing_key else None
        ok = ledger.verify(trusted_key=trusted)
        ledger_verifications.add(1, {"result": "ok" if ok else "broken"})
    return {"ok": ok, "records": len(ledger._records()), "tail_hash": ledger.tail_hash(), "signatures_required": trusted is not None}
