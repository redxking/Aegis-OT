"""Workload identity verification interface and local test implementation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class IdentityVerifier(Protocol):
    @property
    def version(self) -> str: ...

    def verify(self, actor_id: str) -> bool: ...


@dataclass(frozen=True)
class AllowlistIdentityVerifier:
    allowed_actor_ids: frozenset[str]
    version: str = "local-allowlist-v1"

    def verify(self, actor_id: str) -> bool:
        return actor_id in self.allowed_actor_ids
