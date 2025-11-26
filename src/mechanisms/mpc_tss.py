# src/mechanisms/mpc_tss.py
from __future__ import annotations

from typing import Any, Dict, Tuple
import json
import hashlib
import hmac

from core.enums import VerificationFamily
from core.models import Message, MessageMeta, Header, MessageKey
from core.evidence import MPCEvidence, CommitteeAttestation
from core.state import StateManager
from mechanisms.base import Mechanism


class MpcTssMechanism(Mechanism):
    """
    Mechanism implementation for MPC/TSS-style notary bridges.

    Conceptual role
    ----------------
    This mechanism models a typical notary/committee bridge where:
        • A set of off-chain committee nodes observe source-chain events.
        • Each node locally verifies the source event / header.
        • The committee collectively produces a threshold/aggregated signature
          over (m, h_s) or an equivalent commitment.

    In our unified framework, this class is responsible for:
        1. Wrapping an application event `app_event` into a Message `m`.
        2. Constructing a committee attestation over (m, h_s) and embedding
           it into an MPCEvidence object `e`.
        3. Updating the runtime state σ via the StateManager:
              - marking the message as seen (Unique),
              - adding it to the inflight set (Contain-runtime approximation),
              - advancing the per-route sequence counter (Order),
              - optionally relying on StateManager for routing policy (DomainOK).
        4. Not constructing Merkle proofs or state-root-based evidence:
           MPC/TSS bridges typically *do not* expose such proofs to the
           destination chain, so structural chain-level Contain/Final
           checks are not natively supported.
    """

    family = VerificationFamily.MPC_TSS

    def __init__(
        self,
        committee_id: str = "committee-1",
        secret_key: bytes = b"super-secret-key",
    ) -> None:
        """
        Initialize an MPC/TSS mechanism instance.

        Args:
            committee_id:
                Logical identifier of the notary committee. This is embedded
                into the CommitteeAttestation and used by Authentic(e) to
                pick the correct verifier.
            secret_key:
                Shared key used to simulate a threshold signature via HMAC
                in our experimental setting. In a real system this would be
                a threshold key, not a symmetric HMAC key.
        """
        self.committee_id = committee_id
        self.secret_key = secret_key

    # ------------------------------------------------------------------
    # Internal helpers: canonical JSON and HMAC "signature"
    # ------------------------------------------------------------------

    def _sign(self, m: Message, h: Header) -> str:
        """
        Simulate a threshold signature using HMAC-SHA256.

        We deliberately reuse the exact canonicalization used by
        helper.crypto.HmacCommitteeVerifier._canonical_bytes so that
        Authentic(MPC) can re-play the same hashing and verify this
        signature deterministically.

        In a real deployment:
            • The committee would run an MPC/TSS protocol to sign
              a tuple (m, h_s) or a digest thereof.
            • The signature would be verified on-chain by a contract
              keyed with the committee public key.
        """
        from helper.crypto import HmacCommitteeVerifier as HV
        data = HV._canonical_bytes(m, h)  # type: ignore[attr-defined]
        return hmac.new(self.secret_key, data, hashlib.sha256).hexdigest()

    # ------------------------------------------------------------------
    # Mechanism interface implementation
    # ------------------------------------------------------------------

    def build_message_and_evidence(
        self,
        *,
        src_chain_id: str,
        dst_chain_id: str,
        app_event: Dict[str, Any],
        state: StateManager,
        extra: Dict[str, Any] | None = None,
    ) -> Tuple[Message, MPCEvidence]:
        """
        Wrap an application-layer event `app_event` into (m, e)

        Contract for `app_event`
        ------------------------
        We assume the following fields (all are logical, not chain-enforced):

            - "payload": dict
                  Application-level payload (recipient, amount, method, ...).

            - "seq": int
                  Per-channel sequence number for this message.
                  Used by Order / Unique predicates via MessageMeta.

            - "timestamp": int
                  Source-chain or logical timestamp (seconds).

            - "channel": str
                  Logical channel / route identifier (e.g. IBC channel-id).

            - "height": int
                  Source-chain header height under which the message is emitted.

            - "nonce": int (optional)
                  Anti-replay nonce to be bound into the attestation payload.

            - "header_hash": str (optional)
                  Hash of the source-chain header (e.g. block hash) used to
                  populate Header.hash. This allows Authentic(MPC) and other
                  predicates to reason about header identity, even though
                  MPC/TSS does not implement a full light client.

        All of these are *simulated* for our experiments; a real bridge would
        derive them from the source-chain event logs.
        """
        seq = app_event.get("seq", 1)
        timestamp = app_event.get("timestamp", 0)
        channel = app_event.get("channel", "default")
        height = app_event.get("height", 0)
        nonce = app_event.get("nonce", seq)
        payload = app_event.get("payload", {})
        header_hash = app_event.get("header_hash")
        route = (src_chain_id, dst_chain_id, channel)

        # --------------------------------------------------------------
        # 1. Construct the cross-chain message m
        # --------------------------------------------------------------
        meta = MessageMeta(
            seq=seq,
            ttl=None,
            timestamp=timestamp,
            channel=channel,
        )
        m = Message(
            src=src_chain_id,
            dst=dst_chain_id,
            payload=payload,
            meta=meta,
        )

        # --------------------------------------------------------------
        # 2. Construct the header view h_s as seen by the committee
        # --------------------------------------------------------------
        header = Header(
            chain_id=src_chain_id,
            height=height,
            state_root=None,   # MPC/TSS does not verify state roots
            hash=header_hash,  # Optional: use provided header_hash if present
        )

        # --------------------------------------------------------------
        # 3. Produce the committee attestation over (m, h_s)
        # --------------------------------------------------------------
        sig = self._sign(m, header)

        att = CommitteeAttestation(
            committee_id=self.committee_id,
            signature=sig,
            payload={
                "nonce": nonce,
                "seq": seq,
                "channel": channel,
                "timestamp": timestamp,
            },
        )

        e = MPCEvidence(
            family=self.family,
            attestation=att,
            header=header,
            meta=extra or {},
        )


        # --------------------------------------------------------------
        # Return (m, e) to the caller
        # --------------------------------------------------------------
        return m, e
