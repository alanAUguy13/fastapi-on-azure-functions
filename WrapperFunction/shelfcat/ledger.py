"""
Vendored from ShelfCat backend/core/audit_ledger.py — keep byte-compatible with crates/audit-chain.

Tamper-evident hash-chain audit ledger for ShelfCat truth events.

Every accepted Rust Gate event gets chained:
  event_hash = sha256(canonical_json(event_without_hashes) + "|prev=" + prev_hash)

When a signing key is supplied, each record is also Ed25519-signed over
SIGNING_DOMAIN + event_hash. The format is byte-compatible with the Rust
`crates/audit-chain` crate, so either side can verify the other's ledger.

The ledger does not make data immutable by itself, but any edit, deletion, or reorder
breaks verification.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping

from .invariant import EnforcementInvariant

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )


ZERO_HASH = "0" * 64
SIGNING_DOMAIN = "shelfcat.audit.v1:"


@dataclass(frozen=True)
class LedgerRecord:
    sequence: int
    ts_unix_ms: int
    prev_hash: str
    event_hash: str
    event: dict[str, Any]
    signature: str | None = None
    signer: str | None = None


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_event_hash(event: Mapping[str, Any], prev_hash: str) -> str:
    clean = dict(event)
    clean.pop("event_hash", None)
    clean.pop("prev_hash", None)
    clean.pop("ledger_sequence", None)
    clean.pop("ledger_ts_unix_ms", None)
    msg = canonical_json(clean) + "|prev=" + prev_hash
    return hashlib.sha256(msg.encode("utf-8")).hexdigest()


def _signing_message(event_hash: str) -> bytes:
    return (SIGNING_DOMAIN + event_hash).encode("utf-8")


def _public_hex(key: "Ed25519PublicKey") -> str:
    from cryptography.hazmat.primitives import serialization

    return key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class AuditLedger:
    def __init__(self, path: str | Path, signing_key: "Ed25519PrivateKey | None" = None):
        self.path = Path(path)
        self.signing_key = signing_key
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def _records(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def tail_hash(self) -> str:
        records = self._records()
        if not records:
            return ZERO_HASH
        return records[-1]["event_hash"]

    def append_truth_event(self, event: Mapping[str, Any]) -> LedgerRecord:
        EnforcementInvariant.assert_truth_event(event)
        records = self._records()
        prev_hash = records[-1]["event_hash"] if records else ZERO_HASH
        sequence = len(records) + 1
        ts_unix_ms = int(time.time() * 1000)
        event_hash = compute_event_hash(event, prev_hash)

        stamped_event = dict(event)
        stamped_event["prev_hash"] = prev_hash
        stamped_event["event_hash"] = event_hash
        stamped_event["ledger_sequence"] = sequence
        stamped_event["ledger_ts_unix_ms"] = ts_unix_ms

        record: dict[str, Any] = {
            "sequence": sequence,
            "ts_unix_ms": ts_unix_ms,
            "prev_hash": prev_hash,
            "event_hash": event_hash,
            "event": stamped_event,
        }
        if self.signing_key is not None:
            record["signature"] = self.signing_key.sign(_signing_message(event_hash)).hex()
            record["signer"] = _public_hex(self.signing_key.public_key())

        with self.path.open("a", encoding="utf-8") as f:
            f.write(canonical_json(record) + "\n")

        return LedgerRecord(
            sequence=sequence,
            ts_unix_ms=ts_unix_ms,
            prev_hash=prev_hash,
            event_hash=event_hash,
            event=stamped_event,
            signature=record.get("signature"),
            signer=record.get("signer"),
        )

    def verify(self, trusted_key: "Ed25519PublicKey | None" = None) -> bool:
        """
        Recompute the whole chain. With `trusted_key`, every record must also carry
        a valid Ed25519 signature from that key.
        """
        prev = ZERO_HASH
        expected_sequence = 1
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                record = json.loads(line)
                event = record["event"]

                if record["sequence"] != expected_sequence:
                    return False
                if record["prev_hash"] != prev:
                    return False
                if event.get("prev_hash") != prev:
                    return False

                recomputed = compute_event_hash(event, prev)
                if recomputed != record["event_hash"]:
                    return False
                if event.get("event_hash") != record["event_hash"]:
                    return False
                if not self._signature_ok(record, trusted_key):
                    return False

                prev = record["event_hash"]
                expected_sequence += 1
        return True

    @staticmethod
    def _signature_ok(record: Mapping[str, Any], trusted_key: "Ed25519PublicKey | None") -> bool:
        signature = record.get("signature")
        if signature is None:
            return trusted_key is None

        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            key = trusted_key or Ed25519PublicKey.from_public_bytes(bytes.fromhex(record["signer"]))
            key.verify(bytes.fromhex(signature), _signing_message(record["event_hash"]))
        except (InvalidSignature, KeyError, ValueError):
            return False
        return True
