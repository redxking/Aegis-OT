from __future__ import annotations

from datetime import timedelta

from aegis_ot.evidence import EvidenceChain
from aegis_ot.replay import ReplayLedger


def test_evidence_chain_verifies() -> None:
    chain = EvidenceChain()
    chain.append("p1", "d1", {"outcome": "permit"})
    chain.append("p2", "d2", {"outcome": "deny"})
    assert chain.verify()


def test_evidence_tampering_is_detected() -> None:
    chain = EvidenceChain()
    chain.append("p1", "d1", {"outcome": "permit"})
    record = chain.records[0].model_copy(update={"payload": {"outcome": "deny"}})
    chain._records[0] = record  # noqa: SLF001 - deliberate tampering test
    assert not chain.verify()


def test_nonce_expires_after_retention(now) -> None:
    ledger = ReplayLedger(retention=timedelta(seconds=1))
    assert ledger.reserve("nonce", now)
    assert not ledger.reserve("nonce", now)
    assert ledger.reserve("nonce", now + timedelta(seconds=2))
    assert ledger.contains("nonce")


def test_evidence_link_tampering_is_detected() -> None:
    chain = EvidenceChain()
    chain.append("p1", "d1", {"outcome": "permit"})
    chain.append("p2", "d2", {"outcome": "deny"})
    chain._records[1] = chain.records[1].model_copy(  # noqa: SLF001
        update={"previous_hash": "f" * 64}
    )
    assert not chain.verify()


def test_empty_evidence_chain_is_valid() -> None:
    assert EvidenceChain().verify()
