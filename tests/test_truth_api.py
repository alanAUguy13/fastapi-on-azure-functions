import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi.testclient import TestClient

from WrapperFunction import app
from WrapperFunction.shelfcat import api
from WrapperFunction.shelfcat.ledger import ZERO_HASH, compute_event_hash

GATE_KEY = "test-gate-key"
HEADERS = {"X-ShelfCat-Gate-Key": GATE_KEY}


def truth(slot="A1", **extra):
    return {"source": "rust_gate", "validated": True, "store_id": "store-001", "slot_id": slot, **extra}


@pytest.fixture
def client(tmp_path, monkeypatch):
    seed = Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    monkeypatch.setenv("SHELFCAT_LEDGER_PATH", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setenv("SHELFCAT_GATE_API_KEY", GATE_KEY)
    monkeypatch.setenv("SHELFCAT_AUDIT_SIGNING_KEY", seed.hex())
    api.get_ledger.cache_clear()
    yield TestClient(app)
    api.get_ledger.cache_clear()


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_sample_routes_still_work(client):
    assert client.get("/hello/Shivani").json() == {"name": "Shivani"}


def test_append_and_verify(client):
    first = client.post("/v1/truth/events", json=truth("A1"), headers=HEADERS)
    second = client.post("/v1/truth/events", json=truth("A2"), headers=HEADERS)
    assert first.status_code == second.status_code == 201
    assert first.json()["prev_hash"] == ZERO_HASH
    assert second.json()["prev_hash"] == first.json()["event_hash"]
    assert second.json()["signed"] is True

    verify = client.get("/v1/truth/verify").json()
    assert verify == {
        "ok": True, "records": 2, "tail_hash": second.json()["event_hash"], "signatures_required": True,
    }
    assert client.get("/v1/truth/events?limit=1").json()["records"][0]["sequence"] == 2


@pytest.mark.parametrize("event", [
    {"source": "ai_model", "validated": True},
    {"source": "dashboard", "validated": True},
    {"source": "rust_gate", "validated": False},
])
def test_non_gate_writes_forbidden(client, event):
    assert client.post("/v1/truth/events", json=event, headers=HEADERS).status_code == 403
    assert client.get("/v1/truth/verify").json()["records"] == 0


def test_missing_or_wrong_key_unauthorized(client):
    assert client.post("/v1/truth/events", json=truth()).status_code == 401
    assert client.post("/v1/truth/events", json=truth(), headers={"X-ShelfCat-Gate-Key": "nope"}).status_code == 401


def test_writes_disabled_without_configured_key(client, monkeypatch):
    monkeypatch.delenv("SHELFCAT_GATE_API_KEY")
    assert client.post("/v1/truth/events", json=truth(), headers=HEADERS).status_code == 503


def test_tamper_detected(client, tmp_path):
    client.post("/v1/truth/events", json=truth("A1"), headers=HEADERS)
    path = tmp_path / "ledger.jsonl"
    record = json.loads(path.read_text())
    record["event"]["slot_id"] = "Z9"
    path.write_text(json.dumps(record) + "\n")
    assert client.get("/v1/truth/verify").json()["ok"] is False


def test_cross_language_hash_vector():
    """Pinned to the ShelfCat repo's Rust crates/audit-chain vector."""
    event = {
        "source": "rust_gate", "validated": True, "store_id": "store-001",
        "slot_id": "A1", "sku_or_class": "café-crème", "confidence_bp": 9731,
    }
    assert compute_event_hash(event, ZERO_HASH) == "62284867e9afc42ff322b1485730e56a0c340a609c891322a0d34195a1f138a1"


def test_empty_settings_fall_back_to_defaults(monkeypatch):
    """local.settings.json ships these as empty strings."""
    monkeypatch.setenv("SHELFCAT_LEDGER_PATH", "")
    monkeypatch.setenv("SHELFCAT_AUDIT_SIGNING_KEY", "")
    api.get_ledger.cache_clear()
    try:
        ledger = api.get_ledger()
        assert str(ledger.path) == "/tmp/shelfcat/truth-ledger.jsonl"
        assert ledger.signing_key is None
    finally:
        api.get_ledger.cache_clear()
