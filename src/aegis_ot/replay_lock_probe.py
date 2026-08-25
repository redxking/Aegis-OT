"""Small process targets for verifying exclusive replay-ledger ownership."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .capability_plc import OrderlyRestartReplayReservations
from .transport_replay import DurableTransportReplayLedger, TransportReplayLedgerError


def probe_semantic_writer(path: str, connection: Any) -> None:
    """Report whether a child process can acquire one semantic ledger."""

    try:
        ledger = OrderlyRestartReplayReservations(Path(path))
    except ValueError as exc:
        connection.send(("error", str(exc)))
    else:
        connection.send(("acquired", ""))
        ledger.close()
    finally:
        connection.close()


def probe_transport_writer(
    path: str,
    audience: str,
    gateway_key_id: str,
    gateway_public_key_sha256: str,
    connection: Any,
) -> None:
    """Report whether a child process can acquire one transport ledger."""

    try:
        ledger = DurableTransportReplayLedger(
            Path(path),
            audience=audience,
            gateway_key_id=gateway_key_id,
            gateway_public_key_sha256=gateway_public_key_sha256,
        )
    except TransportReplayLedgerError as exc:
        connection.send(("error", str(exc)))
    else:
        connection.send(("acquired", ""))
        ledger.close()
    finally:
        connection.close()
