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

# Use the global ZK verifier defined in helper.crypto
from helper.crypto import GlobalZkVerifier


class ZkLightClientMechanism(Mechanism):
    """
       ZK light-client mechanism implementation.

       Native semantics (real-world model):
         In production systems, a ZK light client works by embedding a
         cryptographic proof system (SNARK/STARK) inside the destination chain.
         The source chain periodically commits its consensus facts
         (e.g., block header, state root, storage slots, validator set hash),
         and a prover circuit generates a succinct proof attesting that:

            - the header is valid under the source chain’s consensus rules;
            - the state_root is correctly derived from the execution state;
            - optional: a Merkle opening confirms that a particular bridge
              storage entry or event log is included under that state_root.

         The verifier contract on the destination chain checks:
            verify(proof, public_inputs) == True

         If verification succeeds, the destination chain safely treats the
         referenced source facts as *final* and *canonical*, enabling strong
         cross-chain predicates like Authentic, Final, and Contain.

       Why we enrich it in this framework:
         The real ZK LC gives us strict cryptographic guarantees, but
         implementations differ widely in:
            - which parts of the header are committed;
            - whether storage proofs or event proofs are also included;
            - how Merkle structures or state transitions are exposed;
            - naming conventions and field structures;
            - whether a per-message commitment exists or only per-header proofs.

         To unify semantics across all mechanism families (§3.1), we provide
         an enriched ZK LC model that:
            - exposes `public_inputs` in a structured and inspectable form;
            - includes message metadata (seq, channel, timestamp) in the
              committed proof inputs, so that DomainBind / Unique / Timely
              predicates can be evaluated consistently across families;
            - optionally attaches a Merkle-contain structure through
              StateManager, enabling Contain(m, h_s) for messages and events;
            - matches GlobalZkVerifier’s commitment rule so that Authentic(e)
              can be uniformly checked inside our Authorizer.

       What is changed or enriched compared to a native ZK LC:
         - We explicitly commit to both header fields and message metadata,
           even though real ZK LCs typically do not commit to per-message data.
         - We include a payload_hash so that the proof ties the message payload
           to the header’s state context.
         - We support optional `zk_extra`, allowing experiments to insert
           additional public inputs, matching different ZK LC designs (Ethereum,
           Mina, Plonky2, IBC-via-ZK, etc.).
         - We use a deterministic commitment (SHA256(canonical(public_inputs)))
           instead of real SNARK pairings or FRI/STARK checks; this allows
           Authentic(e) to be replayed deterministically in experiments.
         - We allow StateManager to mark inflight headers, enabling unified
           implementation of Final(m, e) and Contain(m, h_s), even though
           many native ZK LCs expose only header verification without per-event
           Merkle paths.

       Summary:
         Native ZK light clients prove consensus and sometimes storage/state
         inclusion. Our enriched version adds message-level structure and
         uniform predicate support so that:
            - Authentic(e), HdrRef(e), Final, Contain, DomainBind, Unique,
              Timely can all be evaluated consistently across families.
         The cryptography remains simplified but the logical semantics match
         real-world ZK LC behavior closely enough for threat modeling and
         correctness reasoning.
       """

    family = VerificationFamily.ZK_LIGHT_CLIENT

    # ----------------------------------------------------------------------
    # Helper: canonical JSON (same style as MPC/TSS mechanism)
    # ----------------------------------------------------------------------
    @staticmethod
    def _canonical_json(obj: Any) -> str:
        """
        Convert an object (possibly a pydantic model) into canonical JSON:
          - pydantic -> dict;
          - json.dumps with sorted keys and no extra whitespace.

        This ensures stable hashing across runs and keeps consistency with MPC/TSS.
        """
        data = obj
        if hasattr(obj, "model_dump"):
            data = obj.model_dump(mode="json")
        elif hasattr(obj, "dict"):
            data = obj.dict()
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _sha256_hex(s: str) -> str:
        return hashlib.sha256(s.encode("utf-8")).hexdigest()

    # ----------------------------------------------------------------------
    # Main mechanism interface: convert app_event → (Message, Evidence)
    # ----------------------------------------------------------------------
    def build_message_and_evidence(
        self,
        *,
        src_chain_id: str,
        dst_chain_id: str,
        app_event: Dict[str, Any],
        state: StateManager,
        extra: Dict[str, Any] | None = None,
    ) -> Tuple[Message, ZKLightClientEvidence]:

        # ------------------------------------------------------------------
        # Expected fields from app_event (same convention as MPC/TSS)
        # ------------------------------------------------------------------
        seq = app_event.get("seq", 1)
        timestamp = app_event.get("timestamp", 0)
        channel = app_event.get("channel", "default")
        height = app_event.get("height", 0)
        payload = app_event.get("payload", {})

        state_root = app_event.get("state_root")
        header_hash = app_event.get("header_hash")
        zk_extra = app_event.get("zk_extra") or {}

        route = (src_chain_id, dst_chain_id, channel)

        # ------------------------------------------------------------------
        # 1. Construct message m
        # ------------------------------------------------------------------
        meta = MessageMeta(
            seq=seq,
            ttl=None,           # TTL, if needed, is enforced by the Timely predicate
            timestamp=timestamp,
            channel=channel,
        )

        m = Message(
            src=src_chain_id,
            dst=dst_chain_id,
            payload=payload,
            meta=meta,
        )

        # ------------------------------------------------------------------
        # 2. Construct the source-chain header h_s
        # ------------------------------------------------------------------
        header = Header(
            chain_id=src_chain_id,
            height=height,
            state_root=state_root,
            hash=header_hash,
        )

        # ------------------------------------------------------------------
        # 3. Build public_inputs (before adding commitment)
        #
        # In a real ZK LC, public_inputs must contain exactly what the
        # on-chain verifier will check (header hash, slot, state root...).
        #
        # In this framework, we commit to:
        #     - header (as a plain dict),
        #     - message meta (as a plain dict),
        #     - SHA256 hash of the payload,
        #     - optionally extra fields under "zk_extra".
        # ------------------------------------------------------------------
        header_json = self._canonical_json(header)
        meta_json = self._canonical_json(meta)
        payload_json = self._canonical_json(payload)

        payload_hash = self._sha256_hex(payload_json)

        public_inputs: Dict[str, Any] = {
            "family": self.family.value,
            "header": json.loads(header_json),
            "meta": json.loads(meta_json),
            "payload_hash": payload_hash,
            "zk_extra": zk_extra,
            # "commitment" is added below after computing it.
        }

        # ------------------------------------------------------------------
        # 4. Compute commitment following GlobalZkVerifier's semantics:
        #       commitment = SHA256(canonical(public_inputs_without_commitment))
        #
        # The verifier will recompute the same value for validation.
        # ------------------------------------------------------------------
        pi_no_commit = dict(public_inputs)
        pi_no_commit.pop("commitment", None)

        canonical = json.dumps(
            pi_no_commit,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

        commitment = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        # Attach the commitment to public_inputs so that GlobalZkVerifier
        # can cross-check both public_inputs and proof.
        public_inputs["commitment"] = commitment

        # ------------------------------------------------------------------
        # 5. Construct the proof object
        #
        # A real ZK proof is a structured object. In this framework, the
        # unified rule is:
        #       proof["commitment"] == public_inputs["commitment"]
        #
        # GlobalZkVerifier.verify() will validate it accordingly.
        # ------------------------------------------------------------------
        proof: Dict[str, Any] = {
            "commitment": commitment
        }

        # ------------------------------------------------------------------
        # 6. Construct Evidence e
        # ------------------------------------------------------------------
        e = ZKLightClientEvidence(
            family=self.family,
            proof=proof,
            public_inputs=public_inputs,
            header=header,
            meta=extra or {},
        )


        return m, e
