from __future__ import annotations

"""
Threat scenarios for the Optimistic verification family.

Family:
  - VerificationFamily.OPTIMISTIC

Mechanism:
  - OptimisticMechanism.build_message_and_evidence(...)
    which in our model:
      * constructs a Message m for an application event;
      * produces some optimistic runtimeLayer e (e.g. state root + message root,
        plus information about a dispute window, bonds, etc.);
      * updates evidenceLayer σ:
            - mark_message_seen(MessageKey.from_message(m))
            - add_inflight(key, header_like_view)
            - advance_seq(route, seq)

We do NOT rely on any particular internal shape of the runtimeLayer. We only
assume that:
  - SAFE samples use the mechanism to generate (m, e) on a given header;
  - ATTACK samples either:
      * reuse e but change m, or
      * rely on different header heights in the chain mirror,
    in such a way that our abstract predicates (Contain, DomainOK, Final,
    Unique, Timely, Order, ...) could *in principle* distinguish SAFE vs
    ATTACK.
"""

from typing import List, Tuple, Dict, Any

from core.enums import VerificationFamily
from core.models import Message, MessageMeta, Header
from core.state import StateManager
from experiments.threats_base import ThreatScenario, ThreatId, Label
from experiments.config import ExperimentalStateManager, SimulationChain
from mechanisms.optimistic import OptimisticMechanism


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ensure_chain(state: StateManager, chain_id: str) -> SimulationChain:
    """
    Best-effort helper: obtain (or create) a SimulationChain inside an
    ExperimentalStateManager.

    Optimistic threats assume we have a chain mirror on σ_chain so that
    Final / Contain predicates can reason about headers and "views".
    """
    if not isinstance(state, ExperimentalStateManager):
        raise TypeError("Optimistic threats expect ExperimentalStateManager")

    chain = state.get_chain(chain_id)
    if chain is None:
        chain = SimulationChain(chain_id=chain_id)
        state.attach_chain(chain)
    return chain


# ---------------------------------------------------------------------------
# Threat 1: Inclusion failure (T1_INCLUSION)
# ---------------------------------------------------------------------------

class OptimisticThreat1InclusionScenario(ThreatScenario):
    description = """
    T1_INCLUSION: Inclusion failure for Optimistic bridges.

    Optimistic intuition:
      - A "prover" posts an optimistic claim (runtimeLayer e) about some
        source state h_s. If no one challenges within a dispute window,
        D accepts (m, e) as if m were correctly included under h_s.

    Unified semantic threat:
      - SAFE:
          • Mechanism builds (m_safe, e_safe) for a real event.
          • σ_runtime records inflight(m_safe, h_s) via add_inflight.
      - ATTACK:
          • An attacker forges a different m_attack that was never
            recorded as inflight under h_s on S.
          • They reuse the same optimistic runtimeLayer e_safe.
          • Contain(m, σ_chain / σ_runtime) should accept SAFE and
            reject ATTACK.

    In this simplified model, "inclusion" is approximated via the inflight
    set in σ_runtime, rather than an explicit Merkle membership proof.
    """

    threat_id = ThreatId.T1_INCLUSION
    family = VerificationFamily.OPTIMISTIC

    def __init__(self) -> None:
        self.mech = OptimisticMechanism()

    def generate_trace(
        self,
        state: StateManager,
        kappa: Dict[str, Any] | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, Any, Label]]:
        src_chain = "chain-A"
        dst_chain = "chain-B"
        channel = "chan-1"

        chain = _ensure_chain(state, src_chain)
        header = Header(
            chain_id=src_chain,
            height=100,
            state_root="0x" + "aa" * 32,
            hash="0x" + "01" * 32,
        )
        chain.add_header(header, is_final=True)

        # SAFE: honest inclusion, mechanism records inflight(m_safe)
        safe_event = {
            "payload": {"amount": 100, "to": "bob"},
            "seq": 1,
            "timestamp": 1_700_000_000,
            "channel": channel,
            "height": header.height,
            "state_root": header.state_root,
            "header_hash": header.hash,
        }
        m_safe, e_safe = self.mech.build_message_and_evidence(
            src_chain_id=src_chain,
            dst_chain_id=dst_chain,
            app_event=safe_event,
            state=state,
        )

        # ATTACK: forge a different message but reuse e_safe
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
        e_attack = e_safe  # optimistic "claim" reused for a different m

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_attack, e_attack, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# Threat 2: Domain misbinding (T2_DOMAIN_MISBIND)
# ---------------------------------------------------------------------------

class OptimisticThreat2DomainMisbindScenario(ThreatScenario):
    description = """
    T2_DOMAIN_MISBIND: Domain misbinding for Optimistic bridges.

    Intuition:
      - OPTIMISTIC runtimeLayer e itself often does not fix the (dst, channel)
        domain; routing is handled by application / relayer logic.
      - If the Authorizer does not check DomainOK(m, σ_runtime), then the
        same optimistic claim can be abused to deliver m into a wrong
        destination or channel.

    Scenario:
      - SAFE:
          • (m_safe, e_safe) on route (A → B, "chan-1"), which is in the
            allowed route set of σ_runtime.
      - ATTACK:
          • m_attack rewrites the destination to chain-C (unwhitelisted),
            reusing e_safe; DomainOK(m_attack, σ_runtime) should fail.
    """

    threat_id = ThreatId.T2_DOMAIN_MISBIND
    family = VerificationFamily.OPTIMISTIC

    def __init__(self) -> None:
        self.mech = OptimisticMechanism()

    def generate_trace(
        self,
        state: StateManager,
        kappa: Dict[str, Any] | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, Any, Label]]:
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

        # SAFE: route (A → B, chan-1) which is whitelisted by harness
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

        # ATTACK: same runtimeLayer, but dst changed to chain-C
        meta_attack = MessageMeta(
            seq=m_safe.meta.seq,
            ttl=m_safe.meta.ttl,
            timestamp=m_safe.meta.timestamp,
            channel=m_safe.meta.channel,
        )
        m_attack = Message(
            src=m_safe.src,
            dst=dst_attack,
            payload=m_safe.payload,
            meta=meta_attack,
        )
        e_attack = e_safe

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_attack, e_attack, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# Threat 3: Non-final / ambiguous header (T3_EQUIVOCATION)
# ---------------------------------------------------------------------------

class OptimisticThreat3EquivocationScenario(ThreatScenario):
    description = """
    T3_EQUIVOCATION: Non-final / ambiguous header usage in Optimistic bridges.

    Intuition:
      - Many optimistic designs rely on a "view" of the source chain S
        that may itself be non-final (e.g. L2 state that can be reorged
        or challenged).
      - SAFE:
          • (m_safe, e_safe) is built against a header that the chain
            mirror marks as final.
      - ATTACK:
          • (m_attack, e_attack) is built against a header that is marked
            non-final in SimulationChain.

    Predicates:
      - Authentic_optimistic(e): "no fraud proof observed yet" may hold
        for both.
      - Final(h_s, σ_chain):
          SAFE   → True
          ATTACK → False
    """

    threat_id = ThreatId.T3_EQUIVOCATION
    family = VerificationFamily.OPTIMISTIC

    def __init__(self) -> None:
        self.mech = OptimisticMechanism()

    def generate_trace(
        self,
        state: StateManager,
        kappa: Dict[str, Any] | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, Any, Label]]:
        src_chain = "chain-A"
        dst_chain = "chain-B"
        channel = "chan-3"

        chain = _ensure_chain(state, src_chain)

        # Final header at 200
        header_final = Header(
            chain_id=src_chain,
            height=200,
            state_root="0x" + "cc" * 32,
            hash="0x" + "03" * 32,
        )
        chain.add_header(header_final, is_final=True)

        # Non-final header at 210
        header_nonfinal = Header(
            chain_id=src_chain,
            height=210,
            state_root="0x" + "dd" * 32,
            hash="0x" + "04" * 32,
        )
        chain.add_header(header_nonfinal, is_final=False)

        # SAFE: final header
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

        # ATTACK: non-final header
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

class OptimisticThreat4ReplayScenario(ThreatScenario):
    description = """
    T4_REPLAY: Replay / double-execution for Optimistic bridges.

    Intuition:
      - An optimistic claim (m, e) that has already been accepted on D
        is resubmitted.
      - If σ_runtime does not enforce Unique(m) via MessageKey tracking,
        the application may process the same cross-chain action twice.

    Scenario:
      - SAFE: first appearance of (m, e).
      - ATTACK: second appearance of exactly the same (m, e).
    """

    threat_id = ThreatId.T4_REPLAY
    family = VerificationFamily.OPTIMISTIC

    def __init__(self) -> None:
        self.mech = OptimisticMechanism()

    def generate_trace(
        self,
        state: StateManager,
        kappa: Dict[str, Any] | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, Any, Label]]:
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

        # Replay
        m_replay = m_safe
        e_replay = e_safe

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_replay, e_replay, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# Threat 5: Timeliness / dispute-window / TTL (T5_TIMELINESS)
# ---------------------------------------------------------------------------

class OptimisticThreat5TimelinessScenario(ThreatScenario):
    description = """
    T5_TIMELINESS: Timeliness / dispute-window / TTL for Optimistic bridges.

    Intuition:
      - Optimistic mechanisms have a dispute window: a claim should only
        be "final" after some delay, and may also have an expiry horizon.
      - In our abstract semantics we model this via meta.ttl and a global
        logical time `now` in the Authorizer.

    Scenario:
      - SAFE:
          • m_safe.meta.ttl is large enough so that
                now < m_safe.meta.timestamp + ttl.
      - ATTACK:
          • m_late has the same structure but a much smaller ttl, so
                now >= m_late.meta.timestamp + ttl,
            and Timely(m_late, e_late, now) should fail.

    The harness typically uses now = 1_700_000_999 for reproducibility.
    """

    threat_id = ThreatId.T5_TIMELINESS
    family = VerificationFamily.OPTIMISTIC

    def __init__(self) -> None:
        self.mech = OptimisticMechanism()

    def generate_trace(
        self,
        state: StateManager,
        kappa: Dict[str, Any] | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, Any, Label]]:
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

        # SAFE TTL: large
        m_safe.meta.ttl = 200

        # ATTACK: expired TTL
        m_late = m_safe.copy(deep=True)
        m_late.meta.ttl = 10
        e_late = e_safe

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_late, e_late, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# Threat 6: Ordering / per-route sequence (T6_ORDERING)
# ---------------------------------------------------------------------------

class OptimisticThreat6OrderingScenario(ThreatScenario):
    description = """
    T6_ORDERING: Per-route sequence / ordering violation for Optimistic bridges.

    Intuition:
      - Many optimistic bridges enforce per-channel FIFO ordering using
        monotonically increasing sequence numbers.
      - SAFE:
          • Two messages m1, m2 on (A → B, chan-order) with seq=1, seq=2.
      - ATTACK:
          • A third message m_attack reuses seq=1 on the same route, which
            should be rejected once Order(m, σ_runtime) is enforced.

    We rely on the mechanism to call state.advance_seq(route, seq) on each
    call to build_message_and_evidence.
    """

    threat_id = ThreatId.T6_ORDERING
    family = VerificationFamily.OPTIMISTIC

    def __init__(self) -> None:
        self.mech = OptimisticMechanism()

    def generate_trace(
        self,
        state: StateManager,
        kappa: Dict[str, Any] | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, Any, Label]]:
        src_chain = "chain-A"
        dst_chain = "chain-B"
        channel = "chan-order"

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

        # SAFE #1: seq=1
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

        # SAFE #2: seq=2
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

        # ATTACK: seq=1 again on the same route
        meta_attack = MessageMeta(
            seq=1,
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
        # Evidence: just reuse one of the honest headers via the mechanism's pattern
        e_attack = e2  # optimistic claim still "looks valid", ordering is broken in σ_runtime

        return [
            (m1, e1, Label.SAFE),
            (m2, e2, Label.SAFE),
            (m_attack, e_attack, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# Registry: family → threat_id → scenario
# ---------------------------------------------------------------------------

SCENARIOS_OPTIMISTIC: Dict[ThreatId, ThreatScenario] = {
    ThreatId.T1_INCLUSION:      OptimisticThreat1InclusionScenario(),
    ThreatId.T2_DOMAIN_MISBIND: OptimisticThreat2DomainMisbindScenario(),
    ThreatId.T3_EQUIVOCATION:   OptimisticThreat3EquivocationScenario(),
    ThreatId.T4_REPLAY:         OptimisticThreat4ReplayScenario(),
    ThreatId.T5_TIMELINESS:     OptimisticThreat5TimelinessScenario(),
    ThreatId.T6_ORDERING:       OptimisticThreat6OrderingScenario(),
}
