"""Aegis-OT research runtime assurance package."""

from .gateway import AegisGateway
from .models import ActionProposal, Decision, DecisionOutcome, SystemState

__all__ = ["ActionProposal", "AegisGateway", "Decision", "DecisionOutcome", "SystemState"]
__version__ = "0.1.0"
