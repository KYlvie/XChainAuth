# src/mechanisms/zk_light_client.py
from __future__ import annotations

from typing import Any, Dict, Tuple
import json
import hashlib

from core.enums import VerificationFamily
from core.models import Message, MessageMeta, Header, MessageKey
from core.evidence import ZKLightClientEvidence
from core.state import StateManager
from mechanisms.base import Mechanism


class ZkLightClientMechanism(Mechanism):
    """
    ZK light-client style mechanism implementation.

    Responsibilities:
      - Wrap an application-level event `app_event` into a cross-chain
        Message `m`;
      - Construct a source-header view `h_s` and a corresponding
        ZKLightClientEvidence `e`:
          * `proof`: a (simulated) ZK proof object;
          * `public_inputs`: the committed header / payload data the proof
            is supposed to attest to;
      - Write runtime state into σ (StateManager):
          * replay / Unique state via mark_message_seen();
          * per-route ordering via advance_seq(route, seq);
          * (optionally) inflight tracking via add_inflight().

    In a real deployment, the ZK proof would be generated off-chain by a
    prover circuit, and verified on the destination chain by a verifier
    contract. Here we only model the *shape* of the objects and keep the
    cryptography as a deterministic hash-based stub so that
    Authentic(ZK) can re-check consistency via GlobalZkVerifier.
    """

    family = VerificationFamily.ZK_LIGHT_CLIENT

    # ---- helpers: canonical JSON + simple commitments ----

    @staticmethod
    def _canonical_json(obj: Any) -> str:
        """
        Convert an object (possibly a pydantic model) into a canonical JSON
        string, with stable key ordering and no extra whitespace.

        This mirrors the style used in the MPC mechanism so that hashes are
        reproducible across runs.
        """
        data = obj
        if hasattr(obj, "model_dump"):
            # pydantic v2
            data = obj.model_dump(mode="json")  # type: ignore[call-arg]
        elif hasattr(obj, "dict"):
            # pydantic v1
            data = obj.dict()  # type: ignore[call-arg]

        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _sha256_hex(s: str) -> str:
        return hashlib.sha256(s.encode("utf-8")).hexdigest()

    # ---- Mechanism interface ----

    def build_message_and_evidence(
        self,
        *,
        src_chain_id: str,
        dst_chain_id: str,
        app_event: Dict[str, Any],
        state: StateManager,
        extra: Dict[str, Any] | None = None,
    ) -> Tuple[Message, ZKLightClientEvidence]:
        """
        Package an application event `app_event` into (m, e) for the
        ZK light-client family, and update runtime σ.

        Expected `app_event` fields (informal contract):
          - "payload": dict          → application-level payload
          - "seq": int               → message sequence number
          - "timestamp": int         → source-chain timestamp
          - "channel": str           → channel / route identifier
          - "height": int            → source header height
          - "state_root": str (opt)  → state root committed by the header
          - "header_hash": str (opt) → block / header hash on the source chain
          - "zk_extra": dict (opt)   → extra info to be embedded into
                                       public_inputs if desired

        Notes:
          - This method does *not* attempt to validate the header; it merely
            constructs the objects. Authentic(e) will later call a
            protocol-native ZK verifier to check (proof, public_inputs).
          - We treat ZK as structurally capable of providing Final / Contain
            semantics, but the actual predicates will depend on StateManager’s
            header/state view.
        """
        seq = app_event.get("seq", 1)
        timestamp = app_event.get("timestamp", 0)
        channel = app_event.get("channel", "default")
        height = app_event.get("height", 0)
        payload = app_event.get("payload", {})

        state_root = app_event.get("state_root")
        header_hash = app_event.get("header_hash")
        zk_extra = app_event.get("zk_extra") or {}

        route = (src_chain_id, dst_chain_id, channel)

        # --------------------------------------------------
        # 1. Construct message m
        # --------------------------------------------------
        meta = MessageMeta(
            seq=seq,
            ttl=None,           # TTL, if used, is managed at Timely predicate
            timestamp=timestamp,
            channel=channel,
        )
        m = Message(
            src=src_chain_id,
            dst=dst_chain_id,
            payload=payload,
            meta=meta,
        )

        # --------------------------------------------------
        # 2. Construct source header h_s
        # --------------------------------------------------
        header = Header(
            chain_id=src_chain_id,
            height=height,
            state_root=state_root,
            hash=header_hash,
        )

        # --------------------------------------------------
        # 3. Build public_inputs (without commitment) and dummy ZK proof
        # --------------------------------------------------
        # In a real system, public_inputs must match exactly what the on-chain
        # verifier contract expects (header hash, slot, state root, etc.).
        #
        # For our framework, we:
        #   - include header (as dict),
        #   - include message meta (as dict),
        #   - commit to a hash of the payload,
        #   - embed any extra hints under "zk_extra".
        header_json = self._canonical_json(header)
        meta_json = self._canonical_json(meta)
        payload_json = self._canonical_json(payload)

        payload_hash = self._sha256_hex(payload_json)

        public_inputs: Dict[str, Any] = {
            "family": self.family.value,
            "header": json.loads(header_json),   # header as a plain dict
            "meta": json.loads(meta_json),       # meta as a plain dict
            "payload_hash": payload_hash,
            "zk_extra": zk_extra,
            # NOTE: we will add "commitment" below, after computing it.
        }

        # Compute a commitment that matches GlobalZkVerifier’s semantics:
        #   - take public_inputs WITHOUT the "commitment" field,
        #   - canonical JSON (sorted keys, no whitespace),
        #   - SHA-256 → hex string.
        pi_for_commit = dict(public_inputs)
        # ensure there is no leftover "commitment" key
        pi_for_commit.pop("commitment", None)

        payload_for_commit = json.dumps(
            pi_for_commit,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        commitment = self._sha256_hex(payload_for_commit)

        # Attach commitment to public_inputs so that GlobalZkVerifier can
        # cross-check both:
        #   - public_inputs["commitment"] == recomputed_commitment
        #   - proof["commitment"] == recomputed_commitment
        public_inputs["commitment"] = commitment

        # Our dummy proof just carries the same commitment.
        proof: Dict[str, Any] = {
            "scheme": "dummy-zk-hash",
            "commitment": commitment,
        }

        e = ZKLightClientEvidence(
            family=self.family,
            proof=proof,
            public_inputs=public_inputs,
            header=header,
            meta=extra or {},
        )

        return m, e
