# experiments/mechanism_to_threats/zk_light_client.py
from __future__ import annotations

import json
import hashlib
from typing import List, Tuple, Dict, Any

from core.enums import VerificationFamily
from core.models import Message, MessageMeta, Header
from core.evidence import ZKLightClientEvidence
from core.state import StateManager
from experiments.threats_base import ThreatScenario, ThreatId, Label
from experiments.config import ExperimentalStateManager, SimulationChain


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _canonical_json(obj: Any) -> str:
    """
    Canonical JSON encoding used whenever we want to model a
    message-commitment inside ZK public inputs.

    This mirrors the canonicalization strategy used elsewhere:
      - Pydantic models → model_dump(mode="json")
      - dicts / plain objects → json.dumps(sort_keys=True, ...).
    """
    data = obj
    if hasattr(obj, "model_dump"):
        data = obj.model_dump(mode="json")
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _msg_commitment(m: Message) -> str:
    """
    Simple model of a message commitment: SHA-256 hash of canonical JSON.

    In a real ZK bridge, the circuit would re-compute this commitment
    inside the proof and expose it as a public input.
    """
    js = _canonical_json(m)
    return hashlib.sha256(js.encode("utf-8")).hexdigest()


def _ensure_chain(state: StateManager, chain_id: str) -> SimulationChain:
    """
    Best-effort helper: obtain (or create) a SimulationChain inside an
    ExperimentalStateManager.

    In our standard harness, make_experimental_state_manager_for_family()
    already attaches a SimulationChain("chain-A") for all families, so
    this is mostly a safety net.
    """
    if not isinstance(state, ExperimentalStateManager):
        # In non-experimental environments we do not try to inject chains.
        raise TypeError("ZK LC threats expect ExperimentalStateManager")

    chain = state.get_chain(chain_id)
    if chain is None:
        chain = SimulationChain(chain_id=chain_id)
        state.attach_chain(chain)
    return chain


# ---------------------------------------------------------------------------
# Threat 1: Inclusion failure (T1_INCLUSION)
# ---------------------------------------------------------------------------

class ZkLightClientThreat1InclusionScenario(ThreatScenario):
    description = """
    Threat1 for ZK light clients: Inclusion failure (strong attacker).

    Alignment with unified semantics (matching MPC/TSS Threat1):
      - SAFE:
          • A real application event on S becomes a message m_safe.
          • The ZK circuit proves that m_safe is included under some
            source state rooted at state_root_safe.
          • The proof exposes msg_commitment = H(m_safe) as a public input.
          • D receives (m_safe, e_safe) and accepts it.

      - ATTACK:
          • The attacker forges a different message m_attack that was
            never actually included on the source chain.
          • They replay the same ZK evidence e_safe that was originally
            bound to m_safe (and thus to H(m_safe)).
          • D receives (m_attack, e_safe).

    In an ideal design:
      - Authentic(e) checks the ZK proof.
      - DomainBind / ContextOK(m, e) should check:
            public_inputs["msg_commitment"] == H(m)
        and reject the ATTACK sample.

    In this scenario:
      - SAFE:
          public_inputs["msg_commitment"] = H(m_safe)
      - ATTACK:
          same evidence e_safe is used with a different m_attack.
      - If DomainBind(m, e) is implemented using the commitment, it
        can distinguish SAFE vs ATTACK.
      - If it is not implemented, we can empirically see that ZK LC
        can still be vulnerable to a form of T1.
    """

    threat_id = ThreatId.T1_INCLUSION
    family = VerificationFamily.ZK_LIGHT_CLIENT

    def generate_trace(
        self,
        state: StateManager,
        kappa: Dict[str, Any] | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, ZKLightClientEvidence, Label]]:
        src_chain = "chain-A"
        dst_chain = "chain-B"
        channel = "chan-1"

        chain = _ensure_chain(state, src_chain)

        # ------------------------------------------------------------------
        # SAFE: real event + matching ZK public inputs
        # ------------------------------------------------------------------
        header_safe = Header(
            chain_id=src_chain,
            height=100,
            state_root="0x" + "ab" * 32,
            hash="0x" + "01" * 32,
        )
        chain.add_header(header_safe, is_final=True)

        meta_safe = MessageMeta(
            seq=1,
            ttl=None,
            timestamp=1_700_000_000,
            channel=channel,
        )
        m_safe = Message(
            src=src_chain,
            dst=dst_chain,
            payload={"amount": 100, "to": "bob"},
            meta=meta_safe,
        )

        cm_safe = _msg_commitment(m_safe)

        public_inputs_safe = {
            "src_chain_id": src_chain,
            "dst_chain_id": dst_chain,
            "channel": channel,
            "state_root": header_safe.state_root,
            "header_hash": header_safe.hash,
            "msg_commitment": cm_safe,
        }

        e_safe = ZKLightClientEvidence(
            family=VerificationFamily.ZK_LIGHT_CLIENT,
            proof={"dummy": "proof-safe"},
            public_inputs=public_inputs_safe,
            circuit_id="zk-bridge-v1",
            vk_id="vk-v1",
            header=header_safe,
            meta={"sample": "safe"},
        )

        # ------------------------------------------------------------------
        # ATTACK: different message, same ZK evidence (replay on m)
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
            payload={"amount": 9999, "to": "mallory"},
            meta=meta_attack,
        )

        # Evidence is *identical* to e_safe; only m changes.
        e_attack = e_safe

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_attack, e_attack, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# Threat 2: Domain mis-binding (T2_DOMAIN_MISBIND)
# ---------------------------------------------------------------------------

class ZkLightClientThreat2DomainMisbindScenario(ThreatScenario):
    description = """
    Threat2: Domain mis-binding for ZK light clients.

    Intuition:
      - SAFE:
          • m_safe and e_safe agree on (src, dst, channel);
          • the route (src, dst, channel) is permitted by a DomainOK
            policy in σ_runtime.

      - ATTACK (we model a DomainBind-mismatch variant):
          • m_attack carries a different dst (e.g., chain-C);
          • e_attack's public inputs still claim dst = chain-B
            (public_inputs["dst_chain_id"] ≠ m_attack.dst);
          • public_inputs["msg_commitment"] also still refers to m_safe.

    In a strengthened design:
      - Authentic(e) checks the ZK proof;
      - DomainBind(m, e) checks that commitment and (src, dst, chan)
        in the proof match the message m;
      - DomainOK(m, σ_runtime) checks the route policy.

    In this scenario:
      - SAFE:
          DomainBind = True, DomainOK = True (assuming whitelist);
      - ATTACK:
          DomainBind should be False (the destination and commitment
          do not match m_attack).
    """

    threat_id = ThreatId.T2_DOMAIN_MISBIND
    family = VerificationFamily.ZK_LIGHT_CLIENT

    def generate_trace(
        self,
        state: StateManager,
        kappa: Dict[str, Any] | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, ZKLightClientEvidence, Label]]:
        src_chain = "chain-A"
        dst_chain_safe = "chain-B"
        dst_chain_attack = "chain-C"
        channel = "chan-1"

        chain = _ensure_chain(state, src_chain)

        header = Header(
            chain_id=src_chain,
            height=110,
            state_root="0x" + "cd" * 32,
            hash="0x" + "02" * 32,
        )
        chain.add_header(header, is_final=True)

        # ------------------------------------------------------------------
        # SAFE: m_safe and e_safe agree on (src, dst, channel)
        # ------------------------------------------------------------------
        meta_safe = MessageMeta(
            seq=10,
            ttl=None,
            timestamp=1_700_000_100,
            channel=channel,
        )
        m_safe = Message(
            src=src_chain,
            dst=dst_chain_safe,
            payload={"amount": 50, "to": "alice"},
            meta=meta_safe,
        )
        cm_safe = _msg_commitment(m_safe)

        public_inputs_safe = {
            "src_chain_id": src_chain,
            "dst_chain_id": dst_chain_safe,
            "channel": channel,
            "state_root": header.state_root,
            "header_hash": header.hash,
            "msg_commitment": cm_safe,
        }

        e_safe = ZKLightClientEvidence(
            family=VerificationFamily.ZK_LIGHT_CLIENT,
            proof={"dummy": "proof-domain-safe"},
            public_inputs=public_inputs_safe,
            circuit_id="zk-bridge-v1",
            vk_id="vk-v1",
            header=header,
            meta={"sample": "safe-domain"},
        )

        # ------------------------------------------------------------------
        # ATTACK: m_attack.dst and e_attack.public_inputs["dst_chain_id"]
        #         do not match; msg_commitment also does not match m_attack.
        # ------------------------------------------------------------------
        meta_attack = MessageMeta(
            seq=11,
            ttl=None,
            timestamp=1_700_000_101,
            channel=channel,
        )
        m_attack = Message(
            src=src_chain,
            dst=dst_chain_attack,  # ≠ dst_chain_safe
            payload={"amount": 50, "to": "alice"},
            meta=meta_attack,
        )

        public_inputs_attack = {
            # adversarial: still claims destination is chain-B
            "src_chain_id": src_chain,
            "dst_chain_id": dst_chain_safe,
            "channel": channel,
            "state_root": header.state_root,
            "header_hash": header.hash,
            # message commitment remains committed to m_safe
            "msg_commitment": cm_safe,
            "note": "mismatch between m_attack and e_attack domain/commitment",
        }

        e_attack = ZKLightClientEvidence(
            family=VerificationFamily.ZK_LIGHT_CLIENT,
            proof={"dummy": "proof-domain-attack"},
            public_inputs=public_inputs_attack,
            circuit_id="zk-bridge-v1",
            vk_id="vk-v1",
            header=header,
            meta={"sample": "attack-domain"},
        )

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_attack, e_attack, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# Threat 3: Non-final or equivocated header (T3_EQUIVOCATION)
# ---------------------------------------------------------------------------

class ZkLightClientThreat3EquivocationScenario(ThreatScenario):
    description = """
    Threat3: Non-final or equivocated evidence (T3_EQUIVOCATION) for ZK LC.

    Alignment with the unified semantics (and MPC/TSS Threat3):
      - SAFE:
          • The ZK proof is generated against a canonical header h_final
            at some height h, which the mirror chain marks as final.
      - ATTACK:
          • The proof is generated against an alternative header h_evil:
              - either at the same height with conflicting hash/state_root
                (equivocation), or
              - not present in the mirror chain / marked as non-final.

    In this experiment:
      - We register header_final in SimulationChain with is_final=True;
      - We construct header_evil (same height, different root/hash),
        but do not add it to the chain;
      - SAFE:   e_safe.header = header_final
      - ATTACK: e_attack.header = header_evil

    Semantically:
      - Authentic(e) may be True for both (we treat both as “valid proofs”);
      - HdrRef + Final should:
          SAFE   → True  (header exists in the mirror and is final)
          ATTACK → False (header is unknown / non-final).
    """

    threat_id = ThreatId.T3_EQUIVOCATION
    family = VerificationFamily.ZK_LIGHT_CLIENT

    def generate_trace(
        self,
        state: StateManager,
        kappa: Dict[str, Any] | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, ZKLightClientEvidence, Label]]:
        src_chain = "chain-A"
        dst_chain = "chain-B"
        channel = "chan-1"

        chain = _ensure_chain(state, src_chain)

        # Canonical final header at height 200
        header_final = Header(
            chain_id=src_chain,
            height=200,
            state_root="0x" + "11" * 32,
            hash="0x" + "aa" * 32,
        )
        chain.add_header(header_final, is_final=True)

        # Conflicting / non-final header at the same height
        header_evil = Header(
            chain_id=src_chain,
            height=200,
            state_root="0x" + "22" * 32,
            hash="0x" + "bb" * 32,
        )
        # Note: we do NOT add header_evil to the chain.
        # From σ_chain's perspective, this header does not exist or is not final.

        # ------------------------------------------------------------------
        # SAFE: use header_final
        # ------------------------------------------------------------------
        meta_safe = MessageMeta(
            seq=20,
            ttl=None,
            timestamp=1_700_000_200,
            channel=channel,
        )
        m_safe = Message(
            src=src_chain,
            dst=dst_chain,
            payload={"amount": 1, "to": "carol"},
            meta=meta_safe,
        )
        cm_safe = _msg_commitment(m_safe)

        public_inputs_safe = {
            "src_chain_id": src_chain,
            "dst_chain_id": dst_chain,
            "channel": channel,
            "height": header_final.height,
            "state_root": header_final.state_root,
            "header_hash": header_final.hash,
            "msg_commitment": cm_safe,
        }

        e_safe = ZKLightClientEvidence(
            family=VerificationFamily.ZK_LIGHT_CLIENT,
            proof={"dummy": "proof-equiv-safe"},
            public_inputs=public_inputs_safe,
            circuit_id="zk-bridge-v1",
            vk_id="vk-v1",
            header=header_final,
            meta={"sample": "safe-equiv"},
        )

        # ------------------------------------------------------------------
        # ATTACK: uses header_evil, which σ_chain does not recognize as final
        # ------------------------------------------------------------------
        meta_attack = MessageMeta(
            seq=21,
            ttl=None,
            timestamp=1_700_000_201,
            channel=channel,
        )
        m_attack = Message(
            src=src_chain,
            dst=dst_chain,
            payload={"amount": 1, "to": "carol"},
            meta=meta_attack,
        )
        cm_attack = _msg_commitment(m_attack)

        public_inputs_attack = {
            "src_chain_id": src_chain,
            "dst_chain_id": dst_chain,
            "channel": channel,
            "height": header_evil.height,
            "state_root": header_evil.state_root,
            "header_hash": header_evil.hash,
            "msg_commitment": cm_attack,
            "note": "equivocated / non-final header at same height",
        }

        e_attack = ZKLightClientEvidence(
            family=VerificationFamily.ZK_LIGHT_CLIENT,
            proof={"dummy": "proof-equiv-attack"},
            public_inputs=public_inputs_attack,
            circuit_id="zk-bridge-v1",
            vk_id="vk-v1",
            header=header_evil,
            meta={"sample": "attack-equiv"},
        )

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_attack, e_attack, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# Threat 4: Replay / double-spend (T4_REPLAY)
# ---------------------------------------------------------------------------

class ZkLightClientThreat4ReplayScenario(ThreatScenario):
    description = """
    Threat4: Replay attacks for ZK light clients (T4_REPLAY).

    Intuition (aligned with MPC/TSS Threat4):
      - SAFE:
          • A given (m, e) pair is accepted once on the destination;
      - ATTACK:
          • The identical (m, e) pair is submitted again. If the bridge
            does not enforce a Unique(m) semantics, application effects
            may be executed twice (double-execution / double-spend).

    In this experiment:
      - We construct a single pair (m, e);
      - We return two samples:
          • SAFE:    first appearance of (m, e);
          • ATTACK:  second appearance of the same (m, e).

    Once Unique(m, σ_runtime) is implemented, it can:
      - SAFE:   return True (first time we see the MessageKey);
      - ATTACK: return False (MessageKey already present in σ_runtime.seen).
    """

    threat_id = ThreatId.T4_REPLAY
    family = VerificationFamily.ZK_LIGHT_CLIENT

    def generate_trace(
        self,
        state: StateManager,
        kappa: Dict[str, Any] | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, ZKLightClientEvidence, Label]]:
        src_chain = "chain-A"
        dst_chain = "chain-B"
        channel = "chan-1"

        chain = _ensure_chain(state, src_chain)

        header = Header(
            chain_id=src_chain,
            height=400,
            state_root="0x" + "55" * 32,
            hash="0x" + "ee" * 32,
        )
        chain.add_header(header, is_final=True)

        meta = MessageMeta(
            seq=40,
            ttl=None,
            timestamp=1_700_000_400,
            channel=channel,
        )
        m = Message(
            src=src_chain,
            dst=dst_chain,
            payload={"amount": 123, "to": "erin"},
            meta=meta,
        )
        cm = _msg_commitment(m)

        public_inputs = {
            "src_chain_id": src_chain,
            "dst_chain_id": dst_chain,
            "channel": channel,
            "height": header.height,
            "state_root": header.state_root,
            "header_hash": header.hash,
            "msg_commitment": cm,
        }

        e = ZKLightClientEvidence(
            family=VerificationFamily.ZK_LIGHT_CLIENT,
            proof={"dummy": "proof-replay"},
            public_inputs=public_inputs,
            circuit_id="zk-bridge-v1",
            vk_id="vk-v1",
            header=header,
            meta={"sample": "replay"},
        )

        return [
            (m, e, Label.SAFE),    # first appearance
            (m, e, Label.ATTACK),  # replayed appearance
        ]


# ---------------------------------------------------------------------------
# Threat 5: Timeliness / freshness (T5_TIMELINESS)
# ---------------------------------------------------------------------------

class ZkLightClientThreat5TimelinessScenario(ThreatScenario):
    description = """
    Threat5: Timeliness / freshness violation (T5_TIMELINESS) for ZK LC.

    Intuition (aligned with MPC/TSS Threat5):
      - Messages carry a TTL in meta.ttl, interpreted as a validity
        window relative to meta.timestamp.
      - SAFE:
          • At the chosen logical now, the message has not yet expired
            (timestamp + ttl >= now) and should be accepted.
      - ATTACK:
          • Using the same ZK evidence e, but with a different TTL such
            that the message is expired at the same logical now.

    Key point:
      - The ZK circuit is unaware of TTL semantics; Authentic(e) can
        succeed for both samples.
      - Timely(m, e, now) must separately check
            meta.timestamp + meta.ttl  vs  now
        to reject the attack.
    """

    threat_id = ThreatId.T5_TIMELINESS
    family = VerificationFamily.ZK_LIGHT_CLIENT

    def generate_trace(
        self,
        state: StateManager,
        kappa: Dict[str, Any] | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, ZKLightClientEvidence, Label]]:
        src_chain = "chain-A"
        dst_chain = "chain-B"
        channel = "chan-time"

        chain = _ensure_chain(state, src_chain)

        header = Header(
            chain_id=src_chain,
            height=450,
            state_root="0x" + "99" * 32,
            hash="0x" + "66" * 32,
        )
        chain.add_header(header, is_final=True)

        # SAFE: TTL is long enough relative to a fixed logical now.
        meta_safe = MessageMeta(
            seq=50,
            ttl=None,  # will be set below
            timestamp=1_700_000_900,
            channel=channel,
        )
        m_safe = Message(
            src=src_chain,
            dst=dst_chain,
            payload={"amount": 10, "to": "bob"},
            meta=meta_safe,
        )
        cm_safe = _msg_commitment(m_safe)

        public_inputs_safe = {
            "src_chain_id": src_chain,
            "dst_chain_id": dst_chain,
            "channel": channel,
            "height": header.height,
            "state_root": header.state_root,
            "header_hash": header.hash,
            "msg_commitment": cm_safe,
        }

        e_safe = ZKLightClientEvidence(
            family=VerificationFamily.ZK_LIGHT_CLIENT,
            proof={"dummy": "proof-time-safe"},
            public_inputs=public_inputs_safe,
            circuit_id="zk-bridge-v1",
            vk_id="vk-v1",
            header=header,
            meta={"sample": "safe-time"},
        )

        # TTL choices:
        #   SAFE:   ttl = 200  → 900 + 200 = 1_700_001_100 > now(1_700_000_999)
        #   ATTACK: ttl = 10   → 900 + 10  = 1_700_000_910 < now
        m_safe.meta.ttl = 200

        # ATTACK: copy the message but set a shorter TTL; reuse e_safe.
        m_late = m_safe.copy(deep=True)
        m_late.meta.ttl = 10
        e_late = e_safe

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_late, e_late, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# Threat 6: Ordering / per-channel sequence (T6_ORDERING)
# ---------------------------------------------------------------------------

class ZkLightClientThreat6OrderingScenario(ThreatScenario):
    description = """
    Threat6: Ordering / per-channel sequence confusion (T6_ORDERING).

    Intuition (aligned with MPC/TSS Threat6):
      - For each route = (src, dst, channel), we enforce a monotone
        sequence semantics:
            next_seq(route) starts at 1 and increments by 1.
      - SAFE:
          • The first message on the route with seq=1 is accepted, and
            σ_runtime updates next_seq(route) to 2.
      - ATTACK:
          • Another message on the same route arrives with seq=1 again
            (stale / reordered), which should be rejected by
            Order(m, σ_runtime).

    The ZK circuit itself only sees (m, header, state_root, ...) and
    does not track runtime sequence state, so:
      - Authentic(e) can be True in both samples;
      - Order(m, σ_runtime) is responsible for enforcing per-route
        monotone sequence.
    """

    threat_id = ThreatId.T6_ORDERING
    family = VerificationFamily.ZK_LIGHT_CLIENT

    def generate_trace(
        self,
        state: StateManager,
        kappa: Dict[str, Any] | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, ZKLightClientEvidence, Label]]:
        src_chain = "chain-A"
        dst_chain = "chain-B"
        channel = "chan-1"
        route = (src_chain, dst_chain, channel)

        chain = _ensure_chain(state, src_chain)

        header = Header(
            chain_id=src_chain,
            height=500,
            state_root="0x" + "66" * 32,
            hash="0x" + "ff" * 32,
        )
        chain.add_header(header, is_final=True)

        # ------------------------------------------------------------------
        # SAFE: first message on the route, seq=1
        # ------------------------------------------------------------------
        meta_safe = MessageMeta(
            seq=1,
            ttl=None,
            timestamp=1_700_000_500,
            channel=channel,
        )
        m_safe = Message(
            src=src_chain,
            dst=dst_chain,
            payload={"amount": 5, "to": "frank"},
            meta=meta_safe,
        )
        cm_safe = _msg_commitment(m_safe)

        public_inputs_safe = {
            "src_chain_id": src_chain,
            "dst_chain_id": dst_chain,
            "channel": channel,
            "height": header.height,
            "state_root": header.state_root,
            "header_hash": header.hash,
            "msg_commitment": cm_safe,
        }

        e_safe = ZKLightClientEvidence(
            family=VerificationFamily.ZK_LIGHT_CLIENT,
            proof={"dummy": "proof-order-safe"},
            public_inputs=public_inputs_safe,
            circuit_id="zk-bridge-v1",
            vk_id="vk-v1",
            header=header,
            meta={"sample": "safe-order"},
        )

        # Pre-populate σ_runtime with next_seq(route) = 2,
        # as if the SAFE sample had already been accepted.
        if hasattr(state, "advance_seq"):
            state.advance_seq(route, observed_seq=meta_safe.seq)  # type: ignore[attr-defined]

        # ------------------------------------------------------------------
        # ATTACK: stale / reordered seq=1 again on the same route
        # ------------------------------------------------------------------
        meta_attack = MessageMeta(
            seq=1,  # stale
            ttl=None,
            timestamp=1_700_000_501,
            channel=channel,
        )
        m_attack = Message(
            src=src_chain,
            dst=dst_chain,
            payload={"amount": 5, "to": "frank"},
            meta=meta_attack,
        )
        cm_attack = _msg_commitment(m_attack)

        public_inputs_attack = {
            "src_chain_id": src_chain,
            "dst_chain_id": dst_chain,
            "channel": channel,
            "height": header.height,
            "state_root": header.state_root,
            "header_hash": header.hash,
            "msg_commitment": cm_attack,
            "note": "stale sequence number for this route",
        }

        e_attack = ZKLightClientEvidence(
            family=VerificationFamily.ZK_LIGHT_CLIENT,
            proof={"dummy": "proof-order-attack"},
            public_inputs=public_inputs_attack,
            circuit_id="zk-bridge-v1",
            vk_id="vk-v1",
            header=header,
            meta={"sample": "attack-order"},
        )

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_attack, e_attack, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# Registry: family → threat_id → scenario
# ---------------------------------------------------------------------------

SCENARIOS_ZK_LIGHT_CLIENT: Dict[ThreatId, ThreatScenario] = {
    ThreatId.T1_INCLUSION:      ZkLightClientThreat1InclusionScenario(),
    ThreatId.T2_DOMAIN_MISBIND: ZkLightClientThreat2DomainMisbindScenario(),
    ThreatId.T3_EQUIVOCATION:   ZkLightClientThreat3EquivocationScenario(),
    ThreatId.T4_REPLAY:         ZkLightClientThreat4ReplayScenario(),
    ThreatId.T5_TIMELINESS:     ZkLightClientThreat5TimelinessScenario(),
    ThreatId.T6_ORDERING:       ZkLightClientThreat6OrderingScenario(),
}
