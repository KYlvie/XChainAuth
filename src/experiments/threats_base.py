# core/experiments/threats_base.py
from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Tuple

from core.enums import VerificationFamily
from core.models import Message
from core.evidence import Evidence
from core.state import StateManager


class ThreatId(str, Enum):
    """
    Canonical identifiers for the six threat families in the paper.

    We keep all the variants currently use in code (T1–T6, plus some
    more specific sub-labels) to avoid breaking anything:

      - T1_INCLUSION
          “Inclusion failure”: a message m_attack is accepted on D although
          it is not actually committed under the source state rooted by h_s.
          This is the generic T1 in the paper.

      - T1_TAMPER
          A refinement of T1 where the attacker can only tamper with m
          in transit but *cannot* obtain a fresh valid committee signature
          / proof. In this variant, Authentic(e) should be able to detect
          the attack.

      - T2_DOMAIN_MISBIND
          “Domain misbinding”: the runtimeLayer e is valid for some route or
          domain (S', D', chan'), but is (re)used to authorize a message
          on a different (S, D, chan). This is the cross-domain confusion /
          misbinding threat.

      - T3_EQUIVOCATION
          “Equivocation / conflicting views”: the destination relies on a
          header or state view that is later reverted, or conflicts with
          an alternative view of the same source chain (e.g. BFT equivocation,
          long reorg). This corresponds to using non-final or ambiguous
          headers in cross-chain authorization.

      - T4_REPLAY
          Generic “replay” of a previously valid (m, e) pair, re-used in a
          context where it should no longer be accepted (e.g. after TTL or
          after it has already been consumed).

      - T4_REPLAY_REUSE
          A more specific label for replay / reuse attacks where the *same*
          runtimeLayer object e is intentionally re-used to authorize multiple
          messages, or the same message multiple times, across different
          routes or epochs.

      - T5_TIMELINESS
          “Timeliness / expiry” threats where a message is accepted too late
          (after its TTL / window), or too early (before an optimistic dispute
          window has passed), or in a way that violates liveness expectations.

      - T5_CAUSAL
          A refinement of T5 for *causal* liveness: cross-chain actions that
          should happen in a causally consistent order (e.g. lock → mint →
          burn → unlock) but where delayed / reordered delivery breaks the
          intended causal chain.

      - T6_ORDERING
          “Ordering” threats where messages that should obey some order
          (per-route FIFO, monotone sequence numbers, etc.) are accepted
          out of order, enabling front-running or double-spend style issues.

      - T6_CONTAINMENT
          “Containment” / “message–state binding” threats where a message is
          authorized without being properly contained in the state snapshot
          that the runtimeLayer claims to represent (Merkle / batch opening does
          not actually bind m to the state_root under h_s).

    """

    T5_REPLAY = "T4_replay"
    T4_NONFINAL = "T4_nonfinal"
    T6_ORDERING = "T6_ordering"
    T5_TIMELINESS = "T5_timeliness"
    T4_REPLAY = "T4_replay"

    T1_INCLUSION = "T1_inclusion_failure"
    T1_TAMPER = "T1_inclusion_tampered_only"

    T2_DOMAIN_MISBIND = "T2_domain_misbind"
    T3_EQUIVOCATION = "T3_equivocation"

    T4_REPLAY_REUSE = "T4_replay_reuse"
    T5_CAUSAL = "T5_causal_break"
    T6_CONTAINMENT = "T6_containment_break"


class Label(str, Enum):
    """
    Ground-truth label for each (m, e) sample in a threat trace.

      - SAFE:
          This sample represents a “benign” or honest execution that *should*
          be authorized if the mechanism is working as intended.

      - ATTACK:
          This sample encodes an attack instance that *should* be rejected
          by at least one predicate in the coverage set for the mechanism
          family (if that threat is preventable at all under our model).
    """

    SAFE = "safe"      # should be accepted
    ATTACK = "attack"  # should be rejected


class ThreatScenario(ABC):
    """
    Abstract base class for all family-specific threat scenarios.

    Each concrete scenario corresponds to one ThreatId (e.g. T1_INCLUSION)
    instantiated for one verification family (e.g. MPC_TSS, ZK_LIGHT_CLIENT).

    Conceptually, a ThreatScenario answers the question:

        “If I run this particular cross-chain mechanism family under an
         honest vs. adversarial execution of threat T_k, what sequence of
         (m, e) pairs does the Authorizer on D actually see?”

    The *semantics* of each threat live here, not in the predicates:
    - The scenario decides how the attacker can corrupt messages, headers,
      committee keys, dispute windows, etc.
    - The predicates only see the resulting (m, e, σ) and decide whether to
      authorize or reject.
    """

    # These two attributes must be set as class attributes in subclasses.
    # Example:
    #   class MpcTssThreat1InclusionScenario(ThreatScenario):
    #       threat_id = ThreatId.T1_INCLUSION
    #       family = VerificationFamily.MPC_TSS
    threat_id: ThreatId
    family: VerificationFamily

    @abstractmethod
    def generate_trace(
        self,
        state: StateManager,
        kappa: dict | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, Evidence, Label]]:
        """
        Generate a single “trace” for this (family, threat) scenario.

        Returns:
            A list of (m, e, label) tuples, where:
              - m: Message as seen by the Authorizer on D;
              - e: Evidence object accompanying m;
              - label: SAFE or ATTACK, representing the *ground truth* about
                       whether this pair should be accepted.

        Parameters:
          - state:
              An experiment StateManager instance (e.g. ExperimentalStateManager)
              that acts as the evidenceLayer σ for this run. The scenario is free to
              mutate it to simulate:
                * source-chain headers and finality,
                * routing policy,
                * replay / seen state,
                * dispute windows, etc.

          - kappa:
              Optional “knob” or configuration parameters for this family in
              this scenario (e.g. committee size, depth, dispute window length).
              This allows the same scenario logic to be run under different
              parameter regimes.

          - seed:
              Optional RNG seed if the scenario uses randomness to sample
              adversarial behaviour, message contents, or chain structure.

        The Authorizer / experiment runner does *not* interpret kappa or
        seed directly; they are only for the scenario’s internal use.
        """
        raise NotImplementedError
