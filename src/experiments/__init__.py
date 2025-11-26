# experiments/__init__.py
from __future__ import annotations

from typing import Dict

from core.enums import VerificationFamily
from experiments.config import ExperimentalStateManager, SimulationChain
from experiments.mechanism_to_threats.native_light_client_threats import SCENARIOS_NATIVE_LIGHT_CLIENT
from experiments.mechanism_to_threats.optimistic_threats import SCENARIOS_OPTIMISTIC
from experiments.threats_base import ThreatId, ThreatScenario
from experiments.mechanism_to_threats.mpc_tss_threats import SCENARIOS_MPC_TSS
from experiments.mechanism_to_threats.zk_light_client_threats import SCENARIOS_ZK_LIGHT_CLIENT
from helper.crypto import CommitteeVerifierRegistry, HmacCommitteeVerifier
from core.models import RouteTuple


# ---------------------------------------------------------------------
# 1) Family → ThreatScenario registry
# ---------------------------------------------------------------------

FAMILY_SCENARIOS: Dict[VerificationFamily, Dict[ThreatId, ThreatScenario]] = {
    VerificationFamily.MPC_TSS: SCENARIOS_MPC_TSS,
    VerificationFamily.ZK_LIGHT_CLIENT: SCENARIOS_ZK_LIGHT_CLIENT,
    VerificationFamily.NATIVE_LIGHT_CLIENT: SCENARIOS_NATIVE_LIGHT_CLIENT,
    VerificationFamily.OPTIMISTIC: SCENARIOS_OPTIMISTIC,
}


# ---------------------------------------------------------------------
# 2) Default experimental StateManager for a given family
# ---------------------------------------------------------------------

def make_experimental_state_manager_for_family(
    family: VerificationFamily,
) -> ExperimentalStateManager:
    """
    Construct an ExperimentalStateManager for a given verification family.

    Design:
      - Attach a simulated source chain S (currently fixed to "chain-A").
      - Let ExperimentalStateManager mirror headers/finality from S.
      - Store destination-side runtime state (seen/seq/routes) in the same object.
      - Predicates (Final, Contain, DomainOK, ...) decide how to use this state.
    """
    state = ExperimentalStateManager()

    # Simulated source chain;
    src_chain_id = "chain-A"
    src_chain = SimulationChain(chain_id=src_chain_id)
    state.attach_chain(src_chain)

    # Configure allowed routing policy for DomainOK(m, σ_runtime)
    allowed_route: RouteTuple = (src_chain_id, "chain-B", "chan-1")
    state.set_allowed_routes({allowed_route})

    return state


# ---------------------------------------------------------------------
# 3) Default crypto registry (for MPC_TSS Authentic(e))
# ---------------------------------------------------------------------

DEFAULT_COMMITTEE_ID = "committee-1"
DEFAULT_SECRET_KEY = b"super-secret-key"


def make_default_committee_registry() -> CommitteeVerifierRegistry:
    """
    Construct a default CommitteeVerifierRegistry used in experiments.

    Currently:
      - Registers a single HMAC-based committee verifier
        for MPC/TSS experiments.
    """
    registry = CommitteeVerifierRegistry()
    registry.register(HmacCommitteeVerifier(DEFAULT_COMMITTEE_ID, DEFAULT_SECRET_KEY))
    return registry
