"""Independent topology-consequence evaluator for the bounded M4b experiment.

This package deliberately imports no :mod:`aegis_ot` modules.  It evaluates a
small, registered topology consequence from file-based projections and signs
its report with a process-local Ed25519 identity.  It is not an independent
sensor, AC power-flow solver, or external validation authority.
"""

from .evaluator import (
    ALGORITHM_ID,
    EVALUATOR_ID,
    REPORT_SCHEMA_VERSION,
    REQUEST_SCHEMA_VERSION,
    evaluate_material,
    evaluate_request,
    verify_report,
)

__all__ = [
    "ALGORITHM_ID",
    "EVALUATOR_ID",
    "REPORT_SCHEMA_VERSION",
    "REQUEST_SCHEMA_VERSION",
    "evaluate_material",
    "evaluate_request",
    "verify_report",
]
