"""Canonical hash-chained decision evidence."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from threading import RLock
from typing import Any

from pydantic import BaseModel, ConfigDict


class EvidenceRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    sequence: int
    recorded_at: datetime
    proposal_id: str
    decision_id: str
    previous_hash: str
    payload: dict[str, Any]
    record_hash: str


class EvidenceChain:
    def __init__(self) -> None:
        self._records: list[EvidenceRecord] = []
        self._lock = RLock()

    @staticmethod
    def _digest(data: dict[str, Any]) -> str:
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def append(self, proposal_id: str, decision_id: str, payload: dict[str, Any]) -> EvidenceRecord:
        with self._lock:
            sequence = len(self._records)
            previous_hash = self._records[-1].record_hash if self._records else "0" * 64
            recorded_at = datetime.now(UTC)
            material = {
                "sequence": sequence,
                "recorded_at": recorded_at.isoformat(),
                "proposal_id": proposal_id,
                "decision_id": decision_id,
                "previous_hash": previous_hash,
                "payload": payload,
            }
            record = EvidenceRecord(
                sequence=sequence,
                recorded_at=recorded_at,
                proposal_id=proposal_id,
                decision_id=decision_id,
                previous_hash=previous_hash,
                payload=payload,
                record_hash=self._digest(material),
            )
            self._records.append(record)
            return record

    @property
    def records(self) -> tuple[EvidenceRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def verify(self) -> bool:
        with self._lock:
            previous_hash = "0" * 64
            for record in self._records:
                material = {
                    "sequence": record.sequence,
                    "recorded_at": record.recorded_at.isoformat(),
                    "proposal_id": record.proposal_id,
                    "decision_id": record.decision_id,
                    "previous_hash": record.previous_hash,
                    "payload": record.payload,
                }
                chain_broken = record.previous_hash != previous_hash
                digest_mismatch = record.record_hash != self._digest(material)
                if chain_broken or digest_mismatch:
                    return False
                previous_hash = record.record_hash
            return True
