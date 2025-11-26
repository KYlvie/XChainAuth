# experiments/experiment_runner.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from core.enums import VerificationFamily
from experiments.threats_base import ThreatId
from engine.authorizer import Authorizer

# Centralized experiment configuration
from experiments import (
    FAMILY_SCENARIOS,
    make_experimental_state_manager_for_family,
    make_default_committee_registry,
)


@dataclass
class RunConfig:
    """
    Configuration for a single experimental run:

      - family:   verification family under test
      - threat_id: which threat scenario to instantiate
      - profile:  predicate pipeline profile ("native", "full_stack", ...)
    """
    family: VerificationFamily
    threat_id: ThreatId
    profile: str = "full_stack"   # native / full_stack


def run_single_family_threat(config: RunConfig) -> None:
    """
    Execute a single (family, threat_id, profile) trace through the Authorizer,
    printing each predicate result.

    Responsibilities:
      - obtain the ThreatScenario from FAMILY_SCENARIOS
      - construct an ExperimentalStateManager for the given family
      - ask the scenario to generate a trace (m, e, label) on that state
      - invoke the Authorizer with the chosen predicate profile
      - print per-predicate outcomes for inspection
    """
    # 1) Lookup the scenario
    scenarios = FAMILY_SCENARIOS[config.family]
    scenario = scenarios[config.threat_id]

    # 2) StateManager (source-chain mirror + destination evidenceLayer state)
    state = make_experimental_state_manager_for_family(config.family)

    # 3) Let the threat scenario generate (m, e, label) trace on this state
    traces = scenario.generate_trace(state=state, kappa=None, seed=None)

    # 4) Authorizer with unified predicate pipeline
    authz = Authorizer()

    # 5) Default crypto registry (only relevant for MPC_TSS Authentic(e))
    registry = make_default_committee_registry()

    print(f"=== {config.family.value} / {config.threat_id.value} / profile={config.profile} ===")
    print(scenario.description)
    print()

    for idx, (m, e, label) in enumerate(traces):
        result = authz.authorize(
            m=m,
            e=e,
            family=config.family,
            state=state,
            now=1_700_000_999,  # fixed logical time for reproducibility
            profile=config.profile,
            params={"committee_verifiers": registry},
        )

        print(f"--- sample {idx} ({label.value}) ---")
        print("authorized:", result.authorized, "error:", result.error)

        for pr in result.predicate_results:
            placeholder = None
            if pr.metadata is not None:
                placeholder = pr.metadata.get("placeholder")
            print(
                f"  {pr.name.value:<15} ok={pr.ok} "
                f"reason={pr.reason}"
            )
        print()


# -------------------------------------------------------------------------
# Simple interactive CLI
# -------------------------------------------------------------------------

def _select_family() -> VerificationFamily | None:
    """Interactively select a verification family from FAMILY_SCENARIOS."""
    families: List[VerificationFamily] = list(FAMILY_SCENARIOS.keys())

    print("Available verification families:\n")
    for idx, fam in enumerate(families, start=1):
        print(f"  [{idx}] {fam.value}")
    print("  [q]  quit\n")

    choice = input("Select family index (or 'q' to quit): ").strip().lower()
    if choice in ("q", "quit", "exit"):
        return None

    try:
        idx = int(choice)
    except ValueError:
        print(f"Invalid input: {choice!r}")
        return None

    if idx < 1 or idx > len(families):
        print(f"Index out of range: {idx}")
        return None

    return families[idx - 1]


def _select_threats_for_family(family: VerificationFamily) -> List[ThreatId]:
    """
    Interactively select one or more ThreatId values for a given family.

    Shows all threats with their description, then lets the user choose:
      - a single index (e.g., "1")
      - multiple indices (e.g., "1,3")
      - or "all" to run all threats for that family
    """
    scenarios: Dict[ThreatId, any] = FAMILY_SCENARIOS[family]
    threat_items: List[tuple[ThreatId, any]] = list(scenarios.items())

    print(f"\nThreat scenarios for family {family.value}:\n")
    for idx, (tid, sc) in enumerate(threat_items, start=1):
        # 打印 id + 第一行描述（避免太长）
        desc = sc.description.strip().splitlines()[0] if sc.description else ""
        print(f"  [{idx}] {tid.value}  -  {desc}")

    print("\nEnter threat indices to run, e.g.:")
    print("  '1'       → run threat #1 only")
    print("  '1,3'     → run threat #1 and #3")
    print("  'all'     → run all threats for this family\n")

    raw = input("Your choice: ").strip().lower()

    if raw in ("all", "*"):
        return [tid for (tid, _) in threat_items]

    # parse comma-separated indices
    selected: List[ThreatId] = []
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    for part in parts:
        try:
            idx = int(part)
        except ValueError:
            print(f"Ignoring invalid index: {part!r}")
            continue
        if 1 <= idx <= len(threat_items):
            tid = threat_items[idx - 1][0]
            selected.append(tid)
        else:
            print(f"Ignoring out-of-range index: {idx}")

    if not selected:
        print("No valid threat indices selected; nothing to run.")
    return selected


def _select_profile() -> List[str]:
    """
    Interactively choose which profiles to run:

      - 'native'
      - 'full_stack'
      - 'both' (run both profiles)
    """
    print("\nAvailable profiles:")
    print("  [1] native")
    print("  [2] full_stack")
    print("  [3] both\n")

    choice = input("Select profile (1/2/3, default=3): ").strip()
    if choice == "1":
        return ["native"]
    if choice == "2":
        return ["full_stack"]
    # default or "3"
    return ["native", "full_stack"]


if __name__ == "__main__":
    print("=== Cross-chain authorization experiment runner ===\n")

    family = _select_family()
    if family is None:
        print("Exiting.")
        raise SystemExit(0)

    threats = _select_threats_for_family(family)
    if not threats:
        print("No threats selected. Exiting.")
        raise SystemExit(0)

    profiles = _select_profile()

    print("\n============================================\n")

    for profile in profiles:
        print(f"\n===== Running profile = {profile} for family = {family.value} =====\n")

        for threat_id in threats:
            run_single_family_threat(
                RunConfig(
                    family=family,
                    threat_id=threat_id,
                    profile=profile,
                )
            )
            print("\n" + "=" * 60 + "\n")
