# experiments/mechanism_to_threats/zk_light_client.py
from __future__ import annotations

import json
import hashlib
from typing import List, Tuple, Dict, Any, Optional

from core.enums import VerificationFamily
from core.models import Message, MessageMeta, Header, MessageKey
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
    description= """
    Threat1 for ZK Light Clients: Inclusion failure.

    Intuition (unified semantics):
      - SAFE sample:
          • A real application event on S is turned into a message m_safe.
          • A ZK circuit proves that m_safe is included under a specific
            source state rooted at hs (state_root_safe).
          • D receives (m_safe, e_safe) and accepts it.

      - ATTACK sample:
          • Attacker forges a different message m_attack which was never
            included in the real source state.
          • They *replay* the same ZK evidence e_safe that was originally
            bound to m_safe.
          • D receives (m_attack, e_safe).

    In an ideal ZK LC design:
      - The circuit binds a message commitment cm = H(m) into the proof.
      - Authentic(e) + DomainBind(m, e) should compare:
            cm == H(m)
        and reject the attack sample.

    In our framework:
      - We explicitly place `msg_commitment = H(m_safe)` into
        e_safe.public_inputs.
      - SAFE: m_safe + e_safe → consistent commitment.
      - ATTACK: m_attack + e_safe → mismatching commitment.
      - Whether the pipeline catches this depends on whether
        DomainBind(m, e) (or an equivalent ContextOK check) has been
        activated; the scenario is designed so that such a predicate *could*
        distinguish SAFE vs ATTACK.
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
        # ATTACK: different message, same ZK evidence (replay)
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
    description= """
    Threat2: Domain mis-binding for ZK LC.

    Intuition:
      - SAFE:
          • m_safe and e_safe agree on (src, dst, channel).
          • The (src, dst, channel) triple is also permitted by the
            DomainOK policy in σ_runtime.
      - ATTACK (Domain misbind):
          • Either:
              (a) e_attack is bound to a different (src, dst, channel)
                  than the one carried by m_attack (DomainBind failure); or
              (b) e_attack and m_attack agree, but the route is *not*
                  permitted by DomainOK(m, σ_runtime).

    We model variant (a):
      - SAFE: public_inputs_safe["dst_chain_id"] == m_safe.dst
      - ATTACK: public_inputs_attack["dst_chain_id"] != m_attack.dst

    A properly implemented DomainBind(m, e) predicate should reject the
    attack sample, while SAFE remains accepted.
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
        # ATTACK: m_attack.dst does not match e_attack.public_inputs["dst_chain_id"]
        # ------------------------------------------------------------------
        meta_attack = MessageMeta(
            seq=11,
            ttl=None,
            timestamp=1_700_000_101,
            channel=channel,
        )
        m_attack = Message(
            src=src_chain,
            dst=dst_chain_attack,  # ≠ dst_chain_safe in public_inputs below
            payload={"amount": 50, "to": "alice"},
            meta=meta_attack,
        )
        cm_attack = _msg_commitment(m_attack)

        public_inputs_attack = {
            # adversarial: still claims destination is chain-B
            "src_chain_id": src_chain,
            "dst_chain_id": dst_chain_safe,
            "channel": channel,
            "state_root": header.state_root,
            "header_hash": header.hash,
            # message commitment now differs from m_attack
            "msg_commitment": cm_safe,
            "note": "mismatch between m_attack and e_attack domain",
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
# Threat 3: Header equivocation (T3_EQUIVOCATION)
# ---------------------------------------------------------------------------

class ZkLightClientThreat3EquivocationScenario(ThreatScenario):
    description= """
    Threat3: Header equivocation for ZK light clients.

    Intuition:
      - SAFE:
          • ZK circuit proofs are generated against a canonical header h_can
            on the source chain, with hash H_can.
          • The destination's ZK LC (and our SimulationChain) agree that
            h_can is the valid header at that height.
      - ATTACK:
          • An alternative header h_evil at the *same height* is used as
            the basis for the ZK proof (e_attack), with a different hash
            H_evil or different state_root.
          • The destination chain may or may not have a consistent view
            of which header is canonical.

    In our experimental model:
      - SAFE: header_can is registered in SimulationChain with is_final=True.
      - ATTACK: header_evil is *not* in the chain, or is marked as
        non-final, but the evidence e_attack attempts to rely on it.
      - A well-implemented HdrRef(e) + Final(e) combination should be
        able to distinguish the SAFE and ATTACK cases.
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

        # Canonical header at height 200
        header_can = Header(
            chain_id=src_chain,
            height=200,
            state_root="0x" + "11" * 32,
            hash="0x" + "aa" * 32,
        )
        chain.add_header(header_can, is_final=True)

        # Conflicting header at the *same* height 200, not registered as final
        header_evil = Header(
            chain_id=src_chain,
            height=200,
            state_root="0x" + "22" * 32,
            hash="0x" + "bb" * 32,
        )
        # Note: we do NOT add header_evil to the chain; from σ_chain's
        # perspective this header never existed.

        # ------------------------------------------------------------------
        # SAFE: use canonical header_can
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
            "height": header_can.height,
            "state_root": header_can.state_root,
            "header_hash": header_can.hash,
            "msg_commitment": cm_safe,
        }

        e_safe = ZKLightClientEvidence(
            family=VerificationFamily.ZK_LIGHT_CLIENT,
            proof={"dummy": "proof-equiv-safe"},
            public_inputs=public_inputs_safe,
            circuit_id="zk-bridge-v1",
            vk_id="vk-v1",
            header=header_can,
            meta={"sample": "safe-equiv"},
        )

        # ------------------------------------------------------------------
        # ATTACK: uses equivocated header_evil (not known / not final)
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
            "note": "equivocated header at same height",
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
# Threat 4: Non-final / rollback exposure (T4_NONFINAL)
# ---------------------------------------------------------------------------

class ZkLightClientThreat4NonfinalScenario(ThreatScenario):
    description= """
    Threat4: Non-final / rollback exposure.

    Intuition:
      - SAFE:
          • ZK proof is generated only for headers that are considered
            final (or sufficiently confirmed) by the light client.
      - ATTACK:
          • Proof is generated for a non-final header h_nf which may later
            be rolled back by a reorg or BFT view-change.
          • D accepts (m, e_nf), after which the source chain reverts to a
            different state.

    In our model:
      - SAFE: header_final is added to SimulationChain with is_final=True.
      - ATTACK: header_nonfinal is added with is_final=False.
      - Final(e) should accept SAFE and reject ATTACK.
    """

    threat_id = ThreatId.T4_NONFINAL
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

        # Final header at height 300
        header_final = Header(
            chain_id=src_chain,
            height=300,
            state_root="0x" + "33" * 32,
            hash="0x" + "cc" * 32,
        )
        chain.add_header(header_final, is_final=True)

        # Non-final header at height 310
        header_nonfinal = Header(
            chain_id=src_chain,
            height=310,
            state_root="0x" + "44" * 32,
            hash="0x" + "dd" * 32,
        )
        chain.add_header(header_nonfinal, is_final=False)

        # ------------------------------------------------------------------
        # SAFE: use final header
        # ------------------------------------------------------------------
        meta_safe = MessageMeta(
            seq=30,
            ttl=None,
            timestamp=1_700_000_300,
            channel=channel,
        )
        m_safe = Message(
            src=src_chain,
            dst=dst_chain,
            payload={"amount": 7, "to": "dan"},
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
            proof={"dummy": "proof-final-safe"},
            public_inputs=public_inputs_safe,
            circuit_id="zk-bridge-v1",
            vk_id="vk-v1",
            header=header_final,
            meta={"sample": "safe-final"},
        )

        # ------------------------------------------------------------------
        # ATTACK: non-final header, same pattern
        # ------------------------------------------------------------------
        meta_attack = MessageMeta(
            seq=31,
            ttl=None,
            timestamp=1_700_000_310,
            channel=channel,
        )
        m_attack = Message(
            src=src_chain,
            dst=dst_chain,
            payload={"amount": 7, "to": "dan"},
            meta=meta_attack,
        )
        cm_attack = _msg_commitment(m_attack)

        public_inputs_attack = {
            "src_chain_id": src_chain,
            "dst_chain_id": dst_chain,
            "channel": channel,
            "height": header_nonfinal.height,
            "state_root": header_nonfinal.state_root,
            "header_hash": header_nonfinal.hash,
            "msg_commitment": cm_attack,
            "note": "non-final header used for bridging",
        }

        e_attack = ZKLightClientEvidence(
            family=VerificationFamily.ZK_LIGHT_CLIENT,
            proof={"dummy": "proof-final-attack"},
            public_inputs=public_inputs_attack,
            circuit_id="zk-bridge-v1",
            vk_id="vk-v1",
            header=header_nonfinal,
            meta={"sample": "attack-nonfinal"},
        )

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_attack, e_attack, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# Threat 5: Replay (T5_REPLAY)
# ---------------------------------------------------------------------------

class ZkLightClientThreat5ReplayScenario(ThreatScenario):
    description= """
    Threat5: Replay attacks for ZK LC.

    Intuition:
      - SAFE:
          • A single message instance (identified by MessageKey) is
            accepted once.
      - ATTACK:
          • The same (m, e) pair is delivered multiple times, potentially
            causing double execution of application effects.

    In our experiment:
      - We construct a single pair (m, e) and then:
          • SAFE sample: first appearance of (m, e).
          • ATTACK sample: second appearance of the *same* (m, e).
      - Once the Unique(m) predicate is implemented, it can use
        MessageKey.from_message(m) together with StateManager.has_seen_message
        to reject the ATTACK sample while accepting the SAFE sample.
    """

    threat_id = ThreatId.T5_REPLAY
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

        # Note: We do NOT manually mark_message_seen here; once Unique
        # is implemented, it can choose whether to do this inside the
        # predicate or via the Authorizer.
        return [
            (m, e, Label.SAFE),    # first appearance
            (m, e, Label.ATTACK),  # replayed appearance
        ]


# ---------------------------------------------------------------------------
# Threat 6: Ordering / sequence confusion (T6_ORDERING)
# ---------------------------------------------------------------------------

class ZkLightClientThreat6OrderingScenario(ThreatScenario):
    description= """
    Threat6: Ordering / per-channel sequence confusion.

    Intuition:
      - SAFE:
          • Messages on a given route (src, dst, channel) follow a
            monotone sequence number (seq) discipline.
      - ATTACK:
          • Attacker reorders messages or injects a stale sequence
            number to cause out-of-order authorization on D.

    In our model:
      - We consider a simple per-route monotone sequence policy:
            next_seq(route) starts at 1 and increments by 1.
      - SAFE:
          • m1_safe with seq=1, we *initialize* the route state so that
            next_seq(route) becomes 2.
      - ATTACK:
          • m_attack with seq=1 again on the same route, which should be
            rejected by an Order(m) predicate once it is implemented.

    For now, this scenario prepares σ_runtime so that Order(m) could
    distinguish SAFE vs ATTACK.
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
        # SAFE sample: first message in the route, seq=1
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

        # We pre-populate σ_runtime with the next expected seq = 2,
        # as if m_safe had already been accepted.
        state.advance_seq(route, observed_seq=meta_safe.seq)

        # ------------------------------------------------------------------
        # ATTACK sample: stale / reordered seq=1 again on the same route
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
    ThreatId.T1_INCLUSION: ZkLightClientThreat1InclusionScenario(),
    ThreatId.T2_DOMAIN_MISBIND: ZkLightClientThreat2DomainMisbindScenario(),
    ThreatId.T3_EQUIVOCATION: ZkLightClientThreat3EquivocationScenario(),
    ThreatId.T4_NONFINAL: ZkLightClientThreat4NonfinalScenario(),
    ThreatId.T5_REPLAY: ZkLightClientThreat5ReplayScenario(),
    ThreatId.T6_ORDERING: ZkLightClientThreat6OrderingScenario(),
}
