from __future__ import annotations

"""
Threat scenarios for the Native Light Client family.

Family:
  - VerificationFamily.NATIVE_LIGHT_CLIENT

Evidence type:
  - NativeLightClientEvidence(header, meta)

Mechanism:
  - NativeLightClientMechanism.build_message_and_evidence(...)
    which:
      * constructs Message m
      * obtains a header h_s via ExperimentalStateManager / SimulationChain
        (get_header_view), or falls back to app_event fields
      * updates runtime σ:
            - mark_message_seen(MessageKey.from_message(m))
            - add_inflight(key, header)
            - advance_seq(route, seq)

Goal:
  - For each canonical threat family T1–T6, construct a pair (or sequence)
    of (m, e, label) samples such that the *intended* predicates could
    distinguish SAFE vs ATTACK:

        T1_INCLUSION    → Contain(m, σ_chain / σ_runtime)
        T2_DOMAIN_MISBIND → DomainBind / DomainOK
        T3_EQUIVOCATION → Final / header consistency
        T4_REPLAY       → Unique / replay protection
        T5_TIMELINESS   → Timely / TTL
        T6_ORDERING     → Order / per-route FIFO
"""

from typing import List, Tuple, Dict, Any

from core.enums import VerificationFamily
from core.models import Message, MessageMeta, Header
from core.evidence import NativeLightClientEvidence
from core.state import StateManager
from experiments.threats_base import ThreatScenario, ThreatId, Label
from experiments.config import ExperimentalStateManager, SimulationChain
from mechanisms.native_light_client import NativeLightClientMechanism


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ensure_chain(state: StateManager, chain_id: str) -> SimulationChain:
    """
    Best-effort helper: obtain (or create) a SimulationChain inside an
    ExperimentalStateManager.

    Native LC threats assume we have a chain mirror on σ_chain so that
    Contain / Final predicates can reason about headers.
    """
    if not isinstance(state, ExperimentalStateManager):
        raise TypeError("Native LC threats expect ExperimentalStateManager")

    chain = state.get_chain(chain_id)
    if chain is None:
        chain = SimulationChain(chain_id=chain_id)
        state.attach_chain(chain)
    return chain


# ---------------------------------------------------------------------------
# Threat 1: Inclusion failure (T1_INCLUSION)
# ---------------------------------------------------------------------------

class NativeLightClientThreat1InclusionScenario(ThreatScenario):
    description = """
    T1_INCLUSION: Inclusion failure for Native Light Clients.

    Intuition (unified semantics):
      - SAFE:
          • Mechanism builds (m_safe, e_safe) and records inflight(m_safe, h_s)
            in σ_runtime via state.add_inflight(key, header).
          • A Contain(m, σ_chain / σ_runtime) predicate can later check that
            m_safe is indeed in the "inflight" set under h_s.

      - ATTACK:
          • Attacker forges a different message m_attack that was never
            recorded as inflight under the same h_s.
          • They re-use the same header (and evidence shape), but σ_runtime
            does not contain inflight(m_attack, h_s).
          • Contain(m, σ) should accept SAFE and reject ATTACK.

    Note: In this simplified model, "inclusion" is approximated via the
    inflight set, since NativeLightClientEvidence does not explicitly
    carry a Merkle path; the chain mirror + inflight records stand in for
    a real Merkle membership check.
    """

    threat_id = ThreatId.T1_INCLUSION
    family = VerificationFamily.NATIVE_LIGHT_CLIENT

    def __init__(self) -> None:
        self.mech = NativeLightClientMechanism()

    def generate_trace(
        self,
        state: StateManager,
        kappa: Dict[str, Any] | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, NativeLightClientEvidence, Label]]:
        src_chain = "chain-A"
        dst_chain = "chain-B"
        channel = "chan-1"

        # Ensure the chain mirror has at least one final header at height 100
        chain = _ensure_chain(state, src_chain)
        header_safe = Header(
            chain_id=src_chain,
            height=100,
            state_root="0x" + "aa" * 32,
            hash="0x" + "01" * 32,
        )
        chain.add_header(header_safe, is_final=True)

        # ------------------------------------------------------------------
        # SAFE: mechanism builds (m_safe, e_safe) and records inflight(m_safe)
        # ------------------------------------------------------------------
        safe_event = {
            "payload": {"amount": 100, "to": "bob"},
            "seq": 1,
            "timestamp": 1_700_000_000,
            "channel": channel,
            "height": header_safe.height,
            "state_root": header_safe.state_root,
            "header_hash": header_safe.hash,
        }
        m_safe, e_safe = self.mech.build_message_and_evidence(
            src_chain_id=src_chain,
            dst_chain_id=dst_chain,
            app_event=safe_event,
            state=state,
        )

        # ------------------------------------------------------------------
        # ATTACK: new message m_attack, but NOT recorded as inflight(m_attack)
        # ------------------------------------------------------------------
        meta_attack = MessageMeta(
            seq=2,
            ttl=None,
            timestamp=1_700_000_001,
            channel=channel,
        )
        m_attack = Message(
            src=src_chain,
            dst=dst_chain,
            payload={"amount": 999, "to": "mallory"},
            meta=meta_attack,
        )

        # Re-use the same header from SAFE sample; attacker has no Merkle proof,
        # but NativeLightClientEvidence in our model just carries a header.
        e_attack = NativeLightClientEvidence(
            family=VerificationFamily.NATIVE_LIGHT_CLIENT,
            header=header_safe,
            meta={"sample": "attack-inclusion"},
        )

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_attack, e_attack, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# Threat 2: Domain misbinding (T2_DOMAIN_MISBIND)
# ---------------------------------------------------------------------------

class NativeLightClientThreat2DomainMisbindScenario(ThreatScenario):
    description = """
    T2_DOMAIN_MISBIND: Domain misbinding for Native LC.

    Intuition:
      - SAFE:
          • (m_safe, e_safe) is built for a route that is permitted by
            σ_runtime.DomainOK, e.g. ("chain-A", "chain-B", "chan-1").

      - ATTACK:
          • An attacker reuses the same evidence e_safe (same header h_s)
            but changes the routing domain of the message to an unpermitted
            route (e.g. dst="chain-C").
          • Authentic(e) may still succeed, but DomainOK(m, σ_runtime)
            should reject the attack.

    We rely on:
      - make_experimental_state_manager_for_family() to set an allowed
        route set containing ("chain-A", "chain-B", "chan-1").
    """

    threat_id = ThreatId.T2_DOMAIN_MISBIND
    family = VerificationFamily.NATIVE_LIGHT_CLIENT

    def __init__(self) -> None:
        self.mech = NativeLightClientMechanism()

    def generate_trace(
        self,
        state: StateManager,
        kappa: Dict[str, Any] | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, NativeLightClientEvidence, Label]]:
        src_chain = "chain-A"
        dst_safe = "chain-B"
        dst_attack = "chain-C"
        channel = "chan-1"

        chain = _ensure_chain(state, src_chain)
        header = Header(
            chain_id=src_chain,
            height=110,
            state_root="0x" + "bb" * 32,
            hash="0x" + "02" * 32,
        )
        chain.add_header(header, is_final=True)

        # SAFE: permitted route A → B on "chan-1"
        safe_event = {
            "payload": {"amount": 50, "to": "alice"},
            "seq": 10,
            "timestamp": 1_700_000_050,
            "channel": channel,
            "height": header.height,
            "state_root": header.state_root,
            "header_hash": header.hash,
        }
        m_safe, e_safe = self.mech.build_message_and_evidence(
            src_chain_id=src_chain,
            dst_chain_id=dst_safe,
            app_event=safe_event,
            state=state,
        )

        # ATTACK: change dst to chain-C, reusing same evidence
        meta_attack = MessageMeta(
            seq=m_safe.meta.seq,
            ttl=m_safe.meta.ttl,
            timestamp=m_safe.meta.timestamp,
            channel=m_safe.meta.channel,
        )
        m_attack = Message(
            src=m_safe.src,
            dst=dst_attack,  # not whitelisted
            payload=m_safe.payload,
            meta=meta_attack,
        )
        e_attack = e_safe  # same header, same NativeLightClientEvidence

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_attack, e_attack, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# Threat 3: Non-final / ambiguous header (T3_EQUIVOCATION)
# ---------------------------------------------------------------------------

class NativeLightClientThreat3EquivocationScenario(ThreatScenario):
    description = """
    T3_EQUIVOCATION: Non-final / ambiguous header usage for Native LC.

    Intuition:
      - SAFE:
          • The light client only accepts headers that are final in the
            source-chain mirror (SimulationChain).
          • (m_safe, e_safe) relies on such a final header h_final.

      - ATTACK:
          • A message (m_attack, e_attack) is authorized based on a header
            h_nonfinal that is marked as non-final in the chain mirror.
          • Authentic(e) may still succeed, but Final(h_s, σ_chain) should
            accept SAFE and reject ATTACK.

    In this simplified scenario, we model T3 as "using non-final headers"
    rather than full BFT equivocation with conflicting headers at the same
    height, because SimulationChain stores at most one header per height.
    """

    threat_id = ThreatId.T3_EQUIVOCATION
    family = VerificationFamily.NATIVE_LIGHT_CLIENT

    def __init__(self) -> None:
        self.mech = NativeLightClientMechanism()

    def generate_trace(
        self,
        state: StateManager,
        kappa: Dict[str, Any] | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, NativeLightClientEvidence, Label]]:
        src_chain = "chain-A"
        dst_chain = "chain-B"
        channel = "chan-3"

        chain = _ensure_chain(state, src_chain)

        # Final header at height 200
        header_final = Header(
            chain_id=src_chain,
            height=200,
            state_root="0x" + "cc" * 32,
            hash="0x" + "03" * 32,
        )
        chain.add_header(header_final, is_final=True)

        # Non-final header at height 210
        header_nonfinal = Header(
            chain_id=src_chain,
            height=210,
            state_root="0x" + "dd" * 32,
            hash="0x" + "04" * 32,
        )
        chain.add_header(header_nonfinal, is_final=False)

        # SAFE: uses final header at 200
        safe_event = {
            "payload": {"amount": 7, "to": "carol"},
            "seq": 11,
            "timestamp": 1_700_000_200,
            "channel": channel,
            "height": header_final.height,
            "state_root": header_final.state_root,
            "header_hash": header_final.hash,
        }
        m_safe, e_safe = self.mech.build_message_and_evidence(
            src_chain_id=src_chain,
            dst_chain_id=dst_chain,
            app_event=safe_event,
            state=state,
        )

        # ATTACK: uses non-final header at 210
        attack_event = {
            "payload": {"amount": 8, "to": "dave"},
            "seq": 12,
            "timestamp": 1_700_000_210,
            "channel": channel,
            "height": header_nonfinal.height,
            "state_root": header_nonfinal.state_root,
            "header_hash": header_nonfinal.hash,
        }
        m_attack, e_attack = self.mech.build_message_and_evidence(
            src_chain_id=src_chain,
            dst_chain_id=dst_chain,
            app_event=attack_event,
            state=state,
        )

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_attack, e_attack, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# Threat 4: Replay (T4_REPLAY)
# ---------------------------------------------------------------------------

class NativeLightClientThreat4ReplayScenario(ThreatScenario):
    description = """
    T4_REPLAY: Replay / double-execution for Native LC.

    Intuition:
      - An already-accepted (m, e) pair is submitted again.
      - If σ_runtime does not track MessageKey (Unique(m)), the application
        side-effects may be applied twice.

    Scenario:
      - SAFE: first appearance of (m, e).
      - ATTACK: second appearance of exactly the same (m, e).
    """

    threat_id = ThreatId.T4_REPLAY
    family = VerificationFamily.NATIVE_LIGHT_CLIENT

    def __init__(self) -> None:
        self.mech = NativeLightClientMechanism()

    def generate_trace(
        self,
        state: StateManager,
        kappa: Dict[str, Any] | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, NativeLightClientEvidence, Label]]:
        src_chain = "chain-A"
        dst_chain = "chain-B"
        channel = "chan-replay"

        chain = _ensure_chain(state, src_chain)
        header = Header(
            chain_id=src_chain,
            height=300,
            state_root="0x" + "ee" * 32,
            hash="0x" + "05" * 32,
        )
        chain.add_header(header, is_final=True)

        event = {
            "payload": {"amount": 123, "to": "erin"},
            "seq": 20,
            "timestamp": 1_700_000_300,
            "channel": channel,
            "height": header.height,
            "state_root": header.state_root,
            "header_hash": header.hash,
        }
        m_safe, e_safe = self.mech.build_message_and_evidence(
            src_chain_id=src_chain,
            dst_chain_id=dst_chain,
            app_event=event,
            state=state,
        )

        # Replay the exact same pair
        m_replay = m_safe
        e_replay = e_safe

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_replay, e_replay, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# Threat 5: Timeliness / TTL (T5_TIMELINESS)
# ---------------------------------------------------------------------------

class NativeLightClientThreat5TimelinessScenario(ThreatScenario):
    description = """
    T5_TIMELINESS: TTL / freshness violation for Native LC.

    Intuition:
      - SAFE:
          • m_safe carries a TTL (meta.ttl) such that, at the evaluation
            time `now`, Timely(m, e, now) holds.
      - ATTACK:
          • m_late uses the same basic message / evidence shape, but its
            TTL is too small, so at the same `now` it has expired.

    In the experiment runner, `now` is typically fixed to
      now = 1_700_000_999.
    """

    threat_id = ThreatId.T5_TIMELINESS
    family = VerificationFamily.NATIVE_LIGHT_CLIENT

    def __init__(self) -> None:
        self.mech = NativeLightClientMechanism()

    def generate_trace(
        self,
        state: StateManager,
        kappa: Dict[str, Any] | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, NativeLightClientEvidence, Label]]:
        src_chain = "chain-A"
        dst_chain = "chain-B"
        channel = "chan-time"

        chain = _ensure_chain(state, src_chain)
        header = Header(
            chain_id=src_chain,
            height=400,
            state_root="0x" + "ff" * 32,
            hash="0x" + "06" * 32,
        )
        chain.add_header(header, is_final=True)

        # Base event; we will override TTL on the resulting message
        base_event = {
            "payload": {"amount": 10, "to": "bob"},
            "seq": 30,
            "timestamp": 1_700_000_900,
            "channel": channel,
            "height": header.height,
            "state_root": header.state_root,
            "header_hash": header.hash,
        }
        m_safe, e_safe = self.mech.build_message_and_evidence(
            src_chain_id=src_chain,
            dst_chain_id=dst_chain,
            app_event=base_event,
            state=state,
        )

        # SAFE TTL: large enough so that now=1_700_000_999 < timestamp + ttl
        m_safe.meta.ttl = 200

        # ATTACK: copy message but make TTL too small so it expires
        m_late = m_safe.copy(deep=True)
        m_late.meta.ttl = 10  # timestamp + 10 << now

        # Evidence can be reused; committee / LC does not know TTL
        e_late = e_safe

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_late, e_late, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# Threat 6: Ordering / per-route sequence (T6_ORDERING)
# ---------------------------------------------------------------------------

class NativeLightClientThreat6OrderingScenario(ThreatScenario):
    description = """
    T6_ORDERING: Per-route sequence / ordering violation for Native LC.

    Intuition:
      - We maintain per-route sequence discipline on (src, dst, channel).
      - SAFE:
          • Two messages m1, m2 on the same route with seq=1 then seq=2.
      - ATTACK:
          • A third message m_attack reuses seq=1 on the same route,
            violating monotone order; Order(m, σ_runtime) should reject it.

    The mechanism itself calls state.advance_seq(route, seq) when building
    messages, so σ_runtime will encode the expected next_seq(route).
    """

    threat_id = ThreatId.T6_ORDERING
    family = VerificationFamily.NATIVE_LIGHT_CLIENT

    def __init__(self) -> None:
        self.mech = NativeLightClientMechanism()

    def generate_trace(
        self,
        state: StateManager,
        kappa: Dict[str, Any] | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, NativeLightClientEvidence, Label]]:
        src_chain = "chain-A"
        dst_chain = "chain-B"
        channel = "chan-order"
        route = (src_chain, dst_chain, channel)

        chain = _ensure_chain(state, src_chain)
        header1 = Header(
            chain_id=src_chain,
            height=500,
            state_root="0x" + "aa" * 32,
            hash="0x" + "07" * 32,
        )
        header2 = Header(
            chain_id=src_chain,
            height=501,
            state_root="0x" + "bb" * 32,
            hash="0x" + "08" * 32,
        )
        chain.add_header(header1, is_final=True)
        chain.add_header(header2, is_final=True)

        # SAFE #1: seq = 1
        ev1 = {
            "payload": {"amount": 1, "to": "alice"},
            "seq": 1,
            "timestamp": 1_700_001_000,
            "channel": channel,
            "height": header1.height,
            "state_root": header1.state_root,
            "header_hash": header1.hash,
        }
        m1, e1 = self.mech.build_message_and_evidence(
            src_chain_id=src_chain,
            dst_chain_id=dst_chain,
            app_event=ev1,
            state=state,
        )

        # SAFE #2: seq = 2 (in order)
        ev2 = {
            "payload": {"amount": 2, "to": "bob"},
            "seq": 2,
            "timestamp": 1_700_001_001,
            "channel": channel,
            "height": header2.height,
            "state_root": header2.state_root,
            "header_hash": header2.hash,
        }
        m2, e2 = self.mech.build_message_and_evidence(
            src_chain_id=src_chain,
            dst_chain_id=dst_chain,
            app_event=ev2,
            state=state,
        )

        # ATTACK: seq = 1 again on the same route
        meta_attack = MessageMeta(
            seq=1,  # stale / duplicate
            ttl=None,
            timestamp=1_700_001_002,
            channel=channel,
        )
        m_attack = Message(
            src=src_chain,
            dst=dst_chain,
            payload={"amount": 3, "to": "mallory"},
            meta=meta_attack,
        )

        # Evidence just carries a header; we can reuse header2
        e_attack = NativeLightClientEvidence(
            family=VerificationFamily.NATIVE_LIGHT_CLIENT,
            header=e2.header,
            meta={"sample": "attack-order"},
        )

        return [
            (m1, e1, Label.SAFE),
            (m2, e2, Label.SAFE),
            (m_attack, e_attack, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# Registry: family → threat_id → scenario (for Native LC)
# ---------------------------------------------------------------------------

SCENARIOS_NATIVE_LIGHT_CLIENT: Dict[ThreatId, ThreatScenario] = {
    ThreatId.T1_INCLUSION:      NativeLightClientThreat1InclusionScenario(),
    ThreatId.T2_DOMAIN_MISBIND: NativeLightClientThreat2DomainMisbindScenario(),
    ThreatId.T3_EQUIVOCATION:   NativeLightClientThreat3EquivocationScenario(),
    ThreatId.T4_REPLAY:         NativeLightClientThreat4ReplayScenario(),
    ThreatId.T5_TIMELINESS:     NativeLightClientThreat5TimelinessScenario(),
    ThreatId.T6_ORDERING:       NativeLightClientThreat6OrderingScenario(),
}
