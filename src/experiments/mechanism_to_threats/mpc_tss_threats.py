# experiments/mpc_tss_threats.py
from __future__ import annotations

import hmac
from typing import List, Tuple

from core.enums import VerificationFamily
from core.models import Message, MessageMeta, Header
from core.evidence import MPCEvidence, CommitteeAttestation
from core.state import StateManager
from experiments.threats_base import ThreatScenario, ThreatId, Label
from mechanisms.mpc_tss import MpcTssMechanism


# ---------------------------------------------------------------------------
# Helper: HMAC signature using the same canonical bytes as HmacCommitteeVerifier
# ---------------------------------------------------------------------------

def make_hmac_signature(secret: bytes, m: Message, h: Header) -> str:
    """
    Compute an HMAC-SHA256 signature over (m, h) using exactly the same
    canonical serialization rule as helper.crypto.HmacCommitteeVerifier.

    This ensures that the Authentic(e) predicate can re-verify the
    committee attestation in a bit-identical way (same canonical bytes,
    same MAC).
    """
    from helper.crypto import HmacCommitteeVerifier as HV

    data = HV._canonical_bytes(m, h)  # type: ignore[attr-defined]
    return hmac.new(secret, data, digestmod="sha256").hexdigest()


# ---------------------------------------------------------------------------
# T1: Inclusion failure (strong attacker; structurally undetectable)
# ---------------------------------------------------------------------------

class MpcTssThreat1InclusionScenario(ThreatScenario):
    description = """
    Threat1: Inclusion failure (T1_INCLUSION) for the MPC_TSS notary family.

    Unified semantic meaning:
      - The destination chain D accepts a message m_attack;
      - In the *real* source-chain state, m_attack was never correctly
        recorded or executed;
      - In other words, the evidence e only says “the committee claims to
        have seen m_attack under some header h_s”, but does *not* prove
        that m_attack is verifiably present in the source state.

    For MPC/TSS notary-style bridges, this attack is structurally
    undetectable from the destination-side Authorizer’s perspective:
      - SAFE sample:
          A real event m_safe occurs on the source chain, and an honest
          committee produces (m_safe, e_safe).
      - ATTACK sample:
          An attacker fabricates m_attack that never appears on the source
          chain, yet the committee still produces a valid signature over
          (m_attack, h_s), resulting in e_att.

    For both samples, under our hardened predicate semantics:
      - Authentic(e)   → True  (committee signature is valid)
      - HdrRef(e)      → True  (evidence carries a source header reference)
      - ContextOK(e)   → True  (in our model, the attestation payload binds
                                {nonce, seq, channel, timestamp})
      - Contain(m, σ)  → structurally unsupported for MPC (no inclusion
                          proof capability)
      - Final(h_s)     → structurally unsupported for MPC
      - Other runtime predicates such as Unique / Timely / Order are also
        unsupported in a purely committee-based model.

    Therefore, from the Authorizer’s visible predicate vector, SAFE and
    ATTACK become indistinguishable. This is exactly the phenomenon we
    want to highlight in Chapters 5–6: MPC/TSS notary bridges cannot, at
    the semantic level, defend against inclusion failure.
    """

    threat_id = ThreatId.T1_INCLUSION
    family = VerificationFamily.MPC_TSS

    def __init__(
        self,
        committee_id: str = "committee-1",
        secret_key: bytes = b"super-secret-key",
    ) -> None:
        self.committee_id = committee_id
        self.secret_key = secret_key

        # “Honest mechanism” instance used to construct SAFE samples.
        self.mech = MpcTssMechanism(
            committee_id=self.committee_id,
            secret_key=self.secret_key,
        )

    def generate_trace(
        self,
        state: StateManager,   # Typically ExperimentalStateManager in experiments, but StateManager is enough for typing.
        kappa: dict | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, MPCEvidence, Label]]:
        # ======================================================================
        # 1) SAFE sample: real event m_safe, honest notary produces e_safe
        # ======================================================================
        safe_event = {
            "payload": {"amount": 100, "to": "bob"},
            "seq": 1,
            "timestamp": 1_700_000_000,
            "channel": "chan-1",
            "height": 100,
            # Note: a real-world notary typically does *not* expose any Merkle
            # proof to the destination chain. Hence we do *not* construct
            # leaves/proofs here.
        }
        m_safe, e_safe = self.mech.build_message_and_evidence(
            src_chain_id="chain-A",
            dst_chain_id="chain-B",
            app_event=safe_event,
            state=state,
        )

        # ======================================================================
        # 2) ATTACK sample: structural inclusion failure
        # ======================================================================
        # 2.1 First generate another honest event m_other solely to obtain a
        #     plausibly valid header h_s via e_other.header.
        other_event = {
            "payload": {"amount": 999, "to": "mallory"},
            "seq": 2,
            "timestamp": 1_700_000_001,
            "channel": "chan-1",
            "height": 100,  # Same height for easier comparison.
        }
        _m_other, e_other = self.mech.build_message_and_evidence(
            src_chain_id="chain-A",
            dst_chain_id="chain-B",
            app_event=other_event,
            state=state,
        )

        # 2.2 Construct an attack message m_attack that *never* occurred on S.
        meta_attack = MessageMeta(
            seq=3,
            ttl=None,
            timestamp=1_700_000_002,
            channel="chan-1",
        )
        m_attack = Message(
            src="chain-A",
            dst="chain-B",
            payload={"amount": 42, "to": "alice"},
            meta=meta_attack,
        )

        # 2.3 Reuse e_other.header as if it were a canonical source view,
        #     but produce a fresh, valid signature over (m_attack, h_s).
        header_for_attack = e_other.header
        sig_attack = make_hmac_signature(self.secret_key, m_attack, header_for_attack)

        att_attack = CommitteeAttestation(
            committee_id=self.committee_id,
            signature=sig_attack,
            payload={
                "nonce": meta_attack.seq,
                "seq": meta_attack.seq,
                "channel": meta_attack.channel,
                "timestamp": meta_attack.timestamp,
            },
        )

        e_att = MPCEvidence(
            family=VerificationFamily.MPC_TSS,
            attestation=att_attack,
            header=header_for_attack,
        )

        # From the Authorizer’s vantage point on D:
        #   - (m_safe, e_safe) and (m_attack, e_att) share the same evidence
        #     *shape* and produce an identical predicate vector for all
        #     supported predicates.
        #   - The only semantic difference is that “m_attack never occurred
        #     in the source-chain state”, but since the MPC family has no
        #     Contain / Final capability, this fact is undecidable.
        return [
            (m_safe, e_safe, Label.SAFE),
            (m_attack, e_att, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# T1 (subclass): Tamper-only inclusion (weak attacker; preventable)
# ---------------------------------------------------------------------------

class MpcTssThreat1TamperScenario(ThreatScenario):
    description = """
    Threat1 (subclass): Tamper-only inclusion, attacker cannot re-sign.

    Scenario semantics:
      - On the source chain, a real event m_safe occurs;
      - An honest committee produces e_safe as a valid attestation over
        (m_safe, h_s);
      - Along the S → D message path, an attacker tampers with the message
        payload to obtain m_tampered (e.g., changing amount/to), but reuses
        the original e_safe;
      - The destination-side Authorizer receives (m_tampered, e_safe).

    Samples:
      - SAFE:   (m_safe,    e_safe)
      - ATTACK: (m_tampered, e_safe)

    Since the MPC family’s Authentic(e) predicate re-verifies the committee
    attestation over (m, h_s, signature):
      - SAFE sample:
          verify(m_safe,    h_s, sig_safe) = True
      - ATTACK sample:
          verify(m_tampered, h_s, sig_safe) = False

    Thus:
      - SAFE:   Authentic = True
      - ATTACK: Authentic = False

    In other words, this “tamper-only, no re-sign” variant of inclusion
    failure *is* defendable by Authentic(e) in the MPC/TSS family. It is
    qualitatively different from the structural inclusion failure in T1_INCLUSION,
    where the attacker obtains a fresh valid signature on m_attack.
    """

    threat_id = ThreatId.T1_TAMPER
    family = VerificationFamily.MPC_TSS

    def __init__(
        self,
        committee_id: str = "committee-1",
        secret_key: bytes = b"super-secret-key",
    ) -> None:
        self.committee_id = committee_id
        self.secret_key = secret_key
        self.mech = MpcTssMechanism(
            committee_id=self.committee_id,
            secret_key=self.secret_key,
        )

    def generate_trace(
        self,
        state: StateManager,
        kappa: dict | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, MPCEvidence, Label]]:
        # 1) SAFE sample: honest bridge generates (m_safe, e_safe).
        safe_event = {
            "payload": {"amount": 100, "to": "bob"},
            "seq": 10,
            "timestamp": 1_700_000_100,
            "channel": "chan-2",
            "height": 200,
        }
        m_safe, e_safe = self.mech.build_message_and_evidence(
            src_chain_id="chain-A",
            dst_chain_id="chain-B",
            app_event=safe_event,
            state=state,
        )

        # 2) ATTACK sample: payload is tampered on the wire, but the attacker
        #    cannot obtain a fresh committee signature. The same e_safe is reused.
        meta_tampered = MessageMeta(
            seq=m_safe.meta.seq,
            ttl=m_safe.meta.ttl,
            timestamp=m_safe.meta.timestamp,
            channel=m_safe.meta.channel,
        )
        m_tampered = Message(
            src=m_safe.src,
            dst=m_safe.dst,
            # Tamper the payload (e.g., amount and recipient).
            payload={"amount": 9999, "to": "mallory"},
            meta=meta_tampered,
        )

        # Key point: the attacker reuses the *original* e_safe (same signature).
        e_tampered = e_safe

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_tampered, e_tampered, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# T2: Domain misbinding
# ---------------------------------------------------------------------------

class MpcTssThreat2DomainMisbindScenario(ThreatScenario):
    description = """
    Threat2: Domain misbinding (T2_DOMAIN_MISBIND).

    Intuition:
      - The committee honestly signs for an allowed route:
          Route(m_safe) = ("chain-A", "chain-B", "chan-1")
      - An attacker reuses the same evidence e_safe but rewrites the message's
        routing domain to an *unallowed* route:
          Route(m_attack) = ("chain-A", "chain-C", "chan-1")
      - From the committee’s point of view, this is still a valid signature
        over (m_safe, h_s); the committee itself does not enforce routing
        policy.
      - On the destination chain D, the Authorizer must enforce the cross-
        domain routing policy via DomainOK(m, σ_runtime).

    SAFE:
      - (m_safe, e_safe) and Route(m_safe) is in the runtime whitelist
        maintained in σ_runtime (e.g., via StateManager.set_allowed_routes).

    ATTACK:
      - (m_attack, e_safe) where the signature and header are unchanged,
        but Route(m_attack) is not in the allowed set.

    Expected predicate vector under hardened semantics:
      - Authentic(e): True for both SAFE and ATTACK
      - HdrRef(e):    True for both
      - ContextOK(e): True for both
      - DomainOK(m, σ_runtime):
          SAFE   → True  (route is allowed)
          ATTACK → False (route is not allowed)
    """

    threat_id = ThreatId.T2_DOMAIN_MISBIND
    family = VerificationFamily.MPC_TSS

    def __init__(
        self,
        committee_id: str = "committee-1",
        secret_key: bytes = b"super-secret-key",
    ) -> None:
        self.committee_id = committee_id
        self.secret_key = secret_key
        self.mech = MpcTssMechanism(
            committee_id=self.committee_id,
            secret_key=self.secret_key,
        )

    def generate_trace(
        self,
        state: StateManager,
        kappa: dict | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, MPCEvidence, Label]]:
        # SAFE: permitted route (A → B, chan-1)
        safe_event = {
            "payload": {"amount": 50, "to": "bob"},
            "seq": 5,
            "timestamp": 1_700_000_050,
            "channel": "chan-1",
            "height": 101,
        }
        m_safe, e_safe = self.mech.build_message_and_evidence(
            src_chain_id="chain-A",
            dst_chain_id="chain-B",
            app_event=safe_event,
            state=state,
        )

        # ATTACK: reuse evidence but change routing domain to an unallowed dst.
        meta_attack = MessageMeta(
            seq=m_safe.meta.seq,
            ttl=m_safe.meta.ttl,
            timestamp=m_safe.meta.timestamp,
            channel=m_safe.meta.channel,
        )
        m_attack = Message(
            src=m_safe.src,
            dst="chain-C",  # Not whitelisted by make_experimental_state_manager.
            payload=m_safe.payload,
            meta=meta_attack,
        )
        e_attack = e_safe  # Same signature / header.

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_attack, e_attack, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# T3: Non-final / equivocated evidence
# ---------------------------------------------------------------------------

class MpcTssThreat3EquivocationScenario(ThreatScenario):
    description = """
    Threat3: Non-final or equivocated evidence (T3_EQUIVOCATION).

    Intuition:
      - The Authorizer on D relies on a source-chain view (header / state_root)
        that is *not* final:
          * either the height is not yet final and may be reorged away; or
          * there exist conflicting views at the same height (equivocation).
      - For MPC/TSS, the committee only signs over some header h_s, but does
        not itself prove finality or absence of equivocation.

    We model a hardened setting where D has a light-client-style mirror of S:
      - SAFE:   e_safe.header.height = h_final, and the SimulationChain on S
                marks this height as final;
      - ATTACK: e_att.header.height = h_nonfinal, and the SimulationChain
                does *not* mark it as final (or marks it as non-final /
                conflicting).

    Expected predicate vector (under “with chain mirror” assumptions):
      - Authentic(e): True for both SAFE and ATTACK (committee is honest)
      - Final(h_s, σ_chain):
          SAFE   → True   (height is marked final by the mirrored chain)
          ATTACK → False  (height is non-final / conflicting)
    """

    threat_id = ThreatId.T3_EQUIVOCATION
    family = VerificationFamily.MPC_TSS

    def __init__(
        self,
        committee_id: str = "committee-1",
        secret_key: bytes = b"super-secret-key",
    ) -> None:
        self.committee_id = committee_id
        self.secret_key = secret_key
        self.mech = MpcTssMechanism(
            committee_id=self.committee_id,
            secret_key=self.secret_key,
        )

    def generate_trace(
        self,
        state: StateManager,
        kappa: dict | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, MPCEvidence, Label]]:
        # SAFE header: height 120 is final.
        h_final = Header(
            chain_id="chain-A",
            height=120,
            hash="0xfinal-120",
        )
        # ATTACK header: height 121 exists but is not final.
        h_nonfinal = Header(
            chain_id="chain-A",
            height=121,
            hash="0xnonfinal-121",
        )

        # If state is an ExperimentalStateManager, attach these headers to
        # the simulated chain mirror for Final(h_s, σ_chain) to observe.
        if hasattr(state, "get_chain") and callable(getattr(state, "get_chain")):
            chain = state.get_chain("chain-A")  # type: ignore[attr-defined]
            if chain is not None:
                chain.add_header(h_final, is_final=True)
                chain.add_header(h_nonfinal, is_final=False)

        # SAFE sample: honest event under a final header.
        safe_event = {
            "payload": {"amount": 7, "to": "carol"},
            "seq": 11,
            "timestamp": 1_700_000_120,
            "channel": "chan-3",
            "height": h_final.height,
        }
        m_safe, e_safe = self.mech.build_message_and_evidence(
            src_chain_id="chain-A",
            dst_chain_id="chain-B",
            app_event=safe_event,
            state=state,
        )

        # ATTACK sample: honest committee signs over a non-final header.
        attack_event = {
            "payload": {"amount": 8, "to": "dave"},
            "seq": 12,
            "timestamp": 1_700_000_121,
            "channel": "chan-3",
            "height": h_nonfinal.height,
        }
        m_attack, e_att = self.mech.build_message_and_evidence(
            src_chain_id="chain-A",
            dst_chain_id="chain-B",
            app_event=attack_event,
            state=state,
        )

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_attack, e_att, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# T4: Replay / double-spend
# ---------------------------------------------------------------------------

class MpcTssThreat4ReplayScenario(ThreatScenario):
    description = """
    Threat4: Replay / double-spend (T4_REPLAY).

    Intuition:
      - A previously authorized pair (m, e) is submitted to the Authorizer
        on D *again*, with the evidence unchanged;
      - If the Authorizer does not enforce Unique(m) via a MessageKey and
        σ_runtime.seen, the same cross-chain transfer might be executed
        twice (double-spend).

    SAFE:
      - (m_safe, e_safe) appears for the first time; its MessageKey is not
        yet present in σ_runtime.seen.

    ATTACK:
      - (m_replay, e_replay) is identical to the SAFE sample, but reappears
        after Unique(m) has already marked its key as seen.

    Expected predicate vector under hardened semantics:
      - Authentic(e): True in both SAFE and ATTACK
      - Unique(m, σ_runtime):
          SAFE   → True   (first time we see this MessageKey)
          ATTACK → False  (key already present in σ_runtime.seen)
    """

    threat_id = ThreatId.T4_REPLAY
    family = VerificationFamily.MPC_TSS

    def __init__(
        self,
        committee_id: str = "committee-1",
        secret_key: bytes = b"super-secret-key",
    ) -> None:
        self.committee_id = committee_id
        self.secret_key = secret_key
        self.mech = MpcTssMechanism(
            committee_id=self.committee_id,
            secret_key=self.secret_key,
        )

    def generate_trace(
        self,
        state: StateManager,
        kappa: dict | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, MPCEvidence, Label]]:
        # Normal honest event.
        event = {
            "payload": {"amount": 123, "to": "bob"},
            "seq": 20,
            "timestamp": 1_700_000_200,
            "channel": "chan-replay",
            "height": 300,
        }
        m_safe, e_safe = self.mech.build_message_and_evidence(
            src_chain_id="chain-A",
            dst_chain_id="chain-B",
            app_event=event,
            state=state,
        )

        # Replay: exactly the same message + evidence evaluated at a later time.
        m_replay = m_safe
        e_replay = e_safe

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_replay, e_replay, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# T5: Timeliness / freshness
# ---------------------------------------------------------------------------

class MpcTssThreat5TimelinessScenario(ThreatScenario):
    description = """
    Threat5: Timeliness / freshness violation (T5_TIMELINESS).

    Intuition:
      - The message carries a “validity window” in meta.ttl;
      - SAFE sample arrives within the TTL window;
      - ATTACK sample arrives *after* TTL has expired, but the committee
        signature remains perfectly valid;
      - Timely(m, e, now) must reject these stale messages even though
        Authentic(e) passes.

    In the experiment harness we fix:
      now = 1_700_000_999.
    """

    threat_id = ThreatId.T5_TIMELINESS
    family = VerificationFamily.MPC_TSS

    def __init__(
        self,
        committee_id: str = "committee-1",
        secret_key: bytes = b"super-secret-key",
    ) -> None:
        self.committee_id = committee_id
        self.secret_key = secret_key
        self.mech = MpcTssMechanism(
            committee_id=self.committee_id,
            secret_key=self.secret_key,
        )

    def generate_trace(
        self,
        state: StateManager,
        kappa: dict | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, MPCEvidence, Label]]:
        # SAFE: TTL is in the future relative to now.
        safe_event = {
            "payload": {"amount": 10, "to": "bob"},
            "seq": 30,
            "timestamp": 1_700_000_900,
            "channel": "chan-time",
            "height": 400,
        }
        m_safe, e_safe = self.mech.build_message_and_evidence(
            src_chain_id="chain-A",
            dst_chain_id="chain-B",
            app_event=safe_event,
            state=state,
        )
        # Here we interpret meta.ttl as an absolute deadline for simplicity:
        #   ttl_abs = timestamp + ttl
        # For SAFE:
        #   1_700_000_900 + 200 = 1_700_001_100 > now (1_700_000_999)
        m_safe.meta.ttl = 200

        # ATTACK: same structure but with a much smaller TTL, so that
        #         timestamp + ttl < now, i.e., the message is stale.
        m_late = m_safe.copy(deep=True)
        # 1_700_000_900 + 10 = 1_700_000_910 < now (1_700_000_999).
        m_late.meta.ttl = 10

        # Evidence can be reused: the committee is oblivious to TTL semantics.
        e_late = e_safe

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_late, e_late, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# T6: Ordering / per-route sequence
# ---------------------------------------------------------------------------

class MpcTssThreat6OrderingScenario(ThreatScenario):
    description = """
    Threat6: Channel / workflow ordering violation (T6_ORDERING).

    Intuition:
      - Many bridge protocols require “per-route monotone sequence numbers”:
          for a fixed (src, dst, chan) route, seq must increase monotonically.
      - SAFE: messages arrive in order on a given route (…, 1, 2).
      - ATTACK: an additional message appears with a stale seq (e.g., 1),
        i.e., seq < next_seq, breaking the intended Order(m, σ_runtime)
        constraint.

    SAFE:
      - Two samples on the same route with seq = 1 followed by seq = 2.

    ATTACK:
      - A third sample on the same route reuses seq = 1, triggering an
        ordering violation under hardened semantics.
    """

    threat_id = ThreatId.T6_ORDERING
    family = VerificationFamily.MPC_TSS

    def __init__(
        self,
        committee_id: str = "committee-1",
        secret_key: bytes = b"super-secret-key",
    ) -> None:
        self.committee_id = committee_id
        self.secret_key = secret_key
        self.mech = MpcTssMechanism(
            committee_id=self.committee_id,
            secret_key=self.secret_key,
        )

    def generate_trace(
        self,
        state: StateManager,
        kappa: dict | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, MPCEvidence, Label]]:
        route = ("chain-A", "chain-B", "chan-order")

        # SAFE #1: seq = 1
        ev1 = {
            "payload": {"amount": 1, "to": "alice"},
            "seq": 1,
            "timestamp": 1_700_001_000,
            "channel": route[2],
            "height": 500,
        }
        m1, e1 = self.mech.build_message_and_evidence(
            src_chain_id=route[0],
            dst_chain_id=route[1],
            app_event=ev1,
            state=state,
        )

        # SAFE #2: seq = 2 (in-order)
        ev2 = {
            "payload": {"amount": 2, "to": "bob"},
            "seq": 2,
            "timestamp": 1_700_001_001,
            "channel": route[2],
            "height": 501,
        }
        m2, e2 = self.mech.build_message_and_evidence(
            src_chain_id=route[0],
            dst_chain_id=route[1],
            app_event=ev2,
            state=state,
        )

        # ATTACK: re-use seq = 1 again (out-of-order / duplicate).
        meta_attack = MessageMeta(
            seq=1,  # already consumed
            ttl=None,
            timestamp=1_700_001_002,
            channel=route[2],
        )
        m_attack = Message(
            src=route[0],
            dst=route[1],
            payload={"amount": 3, "to": "mallory"},
            meta=meta_attack,
        )
        # The committee honestly signs m_attack again (we reuse e2.header
        # as the source header h_s).
        sig_attack = make_hmac_signature(self.secret_key, m_attack, e2.header)
        att_attack = CommitteeAttestation(
            committee_id=self.committee_id,
            signature=sig_attack,
            payload={
                "nonce": meta_attack.seq,
                "seq": meta_attack.seq,
                "channel": meta_attack.channel,
                "timestamp": meta_attack.timestamp,
            },
        )
        e_attack = MPCEvidence(
            family=VerificationFamily.MPC_TSS,
            attestation=att_attack,
            header=e2.header,
        )

        return [
            (m1, e1, Label.SAFE),
            (m2, e2, Label.SAFE),
            (m_attack, e_attack, Label.ATTACK),
        ]


# ---------------------------------------------------------------------------
# Registry: MPC_TSS → ThreatId → Scenario
# ---------------------------------------------------------------------------

SCENARIOS_MPC_TSS: dict[ThreatId, ThreatScenario] = {
    ThreatId.T1_INCLUSION:      MpcTssThreat1InclusionScenario(),
    ThreatId.T1_TAMPER:         MpcTssThreat1TamperScenario(),
    ThreatId.T2_DOMAIN_MISBIND: MpcTssThreat2DomainMisbindScenario(),
    ThreatId.T3_EQUIVOCATION:   MpcTssThreat3EquivocationScenario(),
    ThreatId.T4_REPLAY:         MpcTssThreat4ReplayScenario(),
    ThreatId.T5_TIMELINESS:     MpcTssThreat5TimelinessScenario(),
    ThreatId.T6_ORDERING:       MpcTssThreat6OrderingScenario(),
}
