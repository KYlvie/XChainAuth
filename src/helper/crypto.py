# src/crypto.py
from __future__ import annotations

import json
import hmac
import hashlib
from abc import ABC, abstractmethod
from typing import Dict, Optional, Any

from core.models import Message, Header
from core.evidence import MPCEvidence, CommitteeAttestation


class CommitteeVerifier(ABC):
    """
    Abstract interface for verifying committee-produced attestations.

    Intended semantics in the unified framework:

      Given a tuple (m, hs, attestation), the verifier checks whether
      the attestation is *cryptographically valid* for this pair.

      Typical real-world instantiations:
        * MPC / TSS notary:
            - attestation is a threshold- or aggregate signature
              over some commitment to (m, hs) (or digest(m), hs, ...).
        * BFT committee:
            - attestation is an aggregate signature over a block header.

      Our experiments only require a boolean “accept / reject” signal,
      so the interface returns a bool.
    """

    @abstractmethod
    def verify_attestation(
        self,
        m: Message,
        header: Header,
        attestation: CommitteeAttestation,
    ) -> bool:
        """
        Return True if `attestation` is a valid committee proof for (m, header),
        False otherwise.
        """
        raise NotImplementedError


class HmacCommitteeVerifier(CommitteeVerifier):
    """
    Simple HMAC-SHA256-based verifier used in experiments.

    This class is a test stub that simulates a committee verifier
    with symmetric-key authentication instead of real threshold
    signatures.

    Assumptions:
      * attestation.signature is the hex-encoded result of:

            HMAC_SHA256(secret_key, canonical(m, header))

      * canonical(m, header) is a deterministic JSON-based encoding that
        matches the one used by the MpcTssMechanism when it signs.

    In the paper, Authentic(e) for the MPC_TSS family calls into this
    kind of verifier (or an equivalent BLS/ECDSA threshold verifier in
    a real system).
    """

    def __init__(self, committee_id: str, secret_key: bytes) -> None:
        self.committee_id = committee_id
        self.secret_key = secret_key

    @staticmethod
    def _canonical_bytes(m: Message, header: Header) -> bytes:
        """
        Serialize (m, header) into canonical bytes in a pydantic v2–friendly way:

          1. Use model_dump(mode="json") to get plain Python dicts;
          2. Use json.dumps(sort_keys=True, separators=(",", ":"))
             to obtain deterministic JSON;
          3. Concatenate with a clear separator.

        Both the mechanism and the verifier must use *exactly* the same
        encoding, otherwise HMAC verification will fail.
        """
        m_dict = m.model_dump(mode="json")
        h_dict = header.model_dump(mode="json")

        m_json = json.dumps(m_dict, sort_keys=True, separators=(",", ":"))
        h_json = json.dumps(h_dict, sort_keys=True, separators=(",", ":"))

        return m_json.encode("utf-8") + b"||" + h_json.encode("utf-8")

    def verify_attestation(
        self,
        m: Message,
        header: Header,
        attestation: CommitteeAttestation,
    ) -> bool:
        """
        Verify that `attestation.signature` is a valid HMAC over
        canonical(m, header) under this committee's secret key.

        Steps:
          * Check that attestation.committee_id matches this verifier.
          * Recompute HMAC(secret_key, canonical(m, header)).
          * Compare the result with attestation.signature using
            constant-time comparison.
        """
        if attestation.committee_id != self.committee_id:
            return False

        data = self._canonical_bytes(m, header)
        mac = hmac.new(self.secret_key, data, hashlib.sha256).hexdigest()
        return hmac.compare_digest(mac, attestation.signature)


class CommitteeVerifierRegistry:
    """
    Registry for committee verifiers, keyed by committee_id.

    Motivation:
      In many real systems, different committees (or different
      key-sets) may exist simultaneously. The Authorizer, given an
      attestation with a committee_id, needs to dispatch to the correct
      verifier implementation.

    Typical usage pattern:

        registry = CommitteeVerifierRegistry()
        registry.register(HmacCommitteeVerifier("committee-1", secret_key=b"..."))
        ...
        verifier = registry.get(att.committee_id)
        if verifier is None:
            # unknown committee_id → treat as invalid
        else:
            ok = verifier.verify_attestation(m, header, att)

    In the framework, the registry is usually passed down via
    ctx.params["committee_verifiers"].
    """

    def __init__(self) -> None:
        self._verifiers: Dict[str, CommitteeVerifier] = {}

    def register(self, verifier: CommitteeVerifier) -> None:
        """
        Register a verifier under its `committee_id` attribute.

        We assume the concrete verifier exposes a `committee_id`
        attribute; otherwise this method raises a ValueError.
        """
        committee_id = getattr(verifier, "committee_id", None)
        if committee_id is None:
            raise ValueError("Verifier must have a 'committee_id' attribute.")
        self._verifiers[committee_id] = verifier

    def get(self, committee_id: str) -> Optional[CommitteeVerifier]:
        """
        Look up a verifier by committee_id.

        Returns:
          * CommitteeVerifier instance if registered;
          * None if no verifier is known for the given id.
        """
        return self._verifiers.get(committee_id)


class GlobalZkVerifier:
    """
    Simplified global ZK verifier.

    Real-world analogy:
      * In production, ZK verification is usually performed by a
        verifier *contract* deployed on some chain, or by a fixed
        verification function baked into a light-client module.
      * The application / authorizer does *not* get to choose or
        override the verifier at evidenceLayer; it is part of the mechanism.

    In our framework:
      * GlobalZkVerifier is a protocol-internal component.
      * the user cannot simply inject a fake verifier; this matches the on-chain verifier
        semantics.

    Simplified verification rule:

      1. `public_inputs` must be convertible to a dict
         (either already dict, or a pydantic model).
      2. `proof` must be:
           - a dict that contains a field "commitment", or
           - a string, which we interpret directly as the commitment.
      3. We compute a canonical JSON of `public_inputs` with any
         existing "commitment" field removed, then hash it with SHA-256.
         Let this be `recomputed_commitment`.
      4. Verification succeeds iff:

             proof_commitment == recomputed_commitment

         Additionally, if `public_inputs` also has a "commitment" field,
         we require it to match `recomputed_commitment` as well.

    This design allows threat scenarios to control validity:

      * SAFE samples:
          - public_inputs and proof.commitment are consistent →
            verify(...) returns True.

      * ATTACK samples:
          - tamper public_inputs or proof.commitment (or set
            public_inputs["force_invalid"] = True) →
            verify(...) returns False.
    """

    @staticmethod
    def _to_dict(obj: Any) -> Dict[str, Any]:
        """
        Helper: convert various object types into a plain dict.

        Supported inputs:
          * dict → shallow-copied dict
          * pydantic v2 model → obj.model_dump(mode="json")
          * pydantic v1 model → obj.dict()

        Any other type is treated as unsupported and results in a
        TypeError.
        """
        if isinstance(obj, dict):
            return dict(obj)
        if hasattr(obj, "model_dump"):
            # pydantic v2
            return obj.model_dump(mode="json")  # type: ignore[call-arg]
        if hasattr(obj, "dict"):
            # pydantic v1
            return obj.dict()  # type: ignore[call-arg]
        # Fail fast for unsupported input types
        raise TypeError(f"GlobalZkVerifier: unsupported input type {type(obj)}")

    @staticmethod
    def verify(proof: Any, public_inputs: Dict[str, Any]) -> bool:
        """
        Check whether the given (proof, public_inputs) pair is consistent
        with the simplified commitment-based rule.

        Return:
          * True  → proof is accepted as valid under this model.
          * False → proof is rejected (invalid or malformed).
        """
        try:
            pi = GlobalZkVerifier._to_dict(public_inputs)
        except Exception:
            # If we cannot even interpret public_inputs, reject.
            return False

        # Optional control knob: if the caller explicitly sets
        # public_inputs["force_invalid"] = True, we reject regardless
        # of the cryptographic values. This is useful in experiments
        # where we want to force an invalid sample without worrying
        # about the exact encoding.
        if pi.get("force_invalid") is True:
            return False

        # Compute a canonical commitment over public_inputs, ignoring any
        # existing "commitment" field.
        pi_for_commit = dict(pi)
        pi_for_commit.pop("commitment", None)

        payload = json.dumps(
            pi_for_commit,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        recomputed_commitment = hashlib.sha256(payload).hexdigest()

        # Extract commitment from proof:
        proof_commitment: Optional[str] = None
        try:
            if isinstance(proof, str):
                proof_commitment = proof
            else:
                p_dict = GlobalZkVerifier._to_dict(proof)
                c = p_dict.get("commitment")
                if c is not None:
                    proof_commitment = str(c)
        except Exception:
            return False

        if proof_commitment is None:
            # No usable commitment in proof → reject
            return False

        # If public_inputs also carries a "commitment" field, require it
        # to be consistent with our recomputation.
        pi_commitment = pi.get("commitment")
        if pi_commitment is not None and str(pi_commitment) != recomputed_commitment:
            return False

        # Core check: computed commitment must match the one in proof.
        return proof_commitment == recomputed_commitment


class OptimisticVerifier:
    """
    Experimental verifier for an optimistic aggregator.

    Real-world analogy:
      * On-chain, there is a contract/module that:
          - holds the aggregator's public key;
          - exposes a function verify_commitment(commitment, sig),
            which checks a signature against that key.

      * The authorizer (or bridge logic) passes a commitment and a
        signature to that contract and receives True/False.

    In this framework:
      * We simulate that behavior using a single shared secret and HMAC.
      * The goal is not to model the exact crypto, but to provide a
        deterministic, replayable mechanism to distinguish SAFE vs.
        ATTACK traces in experiments.
    """

    # Shared secret for the simulated aggregator.
    # You can override it from your test harness if needed.
    _secret = b"optimistic-aggregator-secret"

    @classmethod
    def set_secret(cls, secret: bytes) -> None:
        """
        Override the global secret used for signing and verification.

        This is mainly for tests or experiments that want to control
        which verifier is considered “honest” or to simulate different
        keys over time.
        """
        cls._secret = secret

    @classmethod
    def sign_commitment(cls, commitment: bytes | str) -> str:
        """
        Produce a simulated aggregator signature over `commitment`.

        The commitment can be:
          * bytes → used directly as the HMAC input;
          * str   → encoded as UTF-8 before HMAC.

        The result is a hex-encoded HMAC-SHA256 under the current
        _secret.
        """
        if isinstance(commitment, str):
            commitment = commitment.encode("utf-8")
        return hmac.new(cls._secret, commitment, digestmod=hashlib.sha256).hexdigest()

    @classmethod
    def verify_commitment(cls, commitment: bytes | str, signature: str) -> bool:
        """
        Verify a simulated aggregator signature for `commitment`.

        This mirrors the real-world contract:

            require(verify(commitment, sig))

        Here we simply recompute the expected HMAC and compare it in
        constant time.

        Returns:
          * True  → signature matches the expected HMAC.
          * False → signature does not match.
        """
        expected = cls.sign_commitment(commitment)
        return hmac.compare_digest(expected, signature)
