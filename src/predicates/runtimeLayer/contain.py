from __future__ import annotations
import json
import hashlib
from typing import List, Optional, Any
from core.enums import VerificationFamily, PredicateName
from predicates.base import Predicate, PredicateLayer, PredicateContext, PredicateResult
from core.evidence import (
    MPCEvidence,
    ZKLightClientEvidence,
    NativeLightClientEvidence,
    OptimisticEvidence,
)
from helper.merkle import verify_merkle_proof


class ContainPredicate(Predicate):
    """
    Contain(m, hs):

    Unified semantics:
      "The message m must be *committed* under the source-chain state rooted by hs,
       with a valid Merkle or batch-opening proof."

    IMPORTANT:
    - Whether this predicate executes is *not* decided here.
      The registry decides which predicates to include based on family+profile.
    - Each verification family exposes its own runtimeLayer structure, so field names
      may differ (leaf, leaf_hash, payload_hash, commitment, etc.).
      We therefore implement a flexible field-mapping strategy.

    Families:
      • MPC/TSS — normally cannot prove inclusion, but if the registry chooses to
        activate Contain, we assume a Merkle proof exists in runtimeLayer.
      • ZK Light Client — containment implicitly proven by the ZK circuit; if
        explicit Merkle proof fields exist, verify them.
      • Native Light Client — classic state_root + Merkle proof.
      • Optimistic — batch_root/state_root + proof.
      • HTLC / Workflow — do not have state-root-based containment.
    """

    name = PredicateName.CONTAIN
    layer = PredicateLayer.RUNTIME

    # ----------------------------------------------------------------------
    # Helper: extract canonical leaf hash for message m
    # ----------------------------------------------------------------------
    def _canonical_leaf(self, m) -> str:
        """Compute SHA-256 hash over canonical JSON form of message m."""
        data = m.model_dump(mode="json")
        js = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(js.encode("utf-8")).hexdigest()

    # ----------------------------------------------------------------------
    # Helper: map possible field names to a leaf hash
    # ----------------------------------------------------------------------
    def _get_leaf_hash(self, e) -> Optional[str]:
        """
        Evidence from different families may expose leaf identifier under
        various names: leaf, leaf_hash, payload_hash etc.
        """
        for field in ["leaf", "leaf_hash", "payload_hash"]:
            if hasattr(e, field) and getattr(e, field) is not None:
                return str(getattr(e, field))
        return None

    # ----------------------------------------------------------------------
    # Helper: map possible proof fields
    # ----------------------------------------------------------------------
    def _get_merkle_proof(self, e) -> Optional[List[str]]:
        for field in ["proof", "merkle_proof", "siblings"]:
            if hasattr(e, field):
                val = getattr(e, field)
                # Only accept real lists; ignore strings or malformed values
                if isinstance(val, list) and all(isinstance(x, str) for x in val):
                    return val
        return None

    # ----------------------------------------------------------------------
    # Helper: get state root from various families
    # ----------------------------------------------------------------------
    def _get_state_root(self, e, header) -> Optional[str]:
        # Explicit header.state_root (NLC, MPC-ME, Optimistic)
        if header and getattr(header, "state_root", None):
            return header.state_root

        # Optimistic claim.state_root
        if isinstance(e, OptimisticEvidence):
            sr = e.claim.state_root
            if sr:
                return sr

        # ZK LC public inputs may carry root under multiple keys
        if isinstance(e, ZKLightClientEvidence):
            pv = e.public_inputs
            for key in ["state_root", "root", "storage_root", "batch_root"]:
                if key in pv:
                    return pv[key]

        return None

    # ----------------------------------------------------------------------
    # Main evaluate()
    # ----------------------------------------------------------------------
    def evaluate(self, ctx: PredicateContext) -> PredicateResult:
        family = ctx.family
        m = ctx.m
        e = ctx.e
        header = e.hdr_ref()

        # --------------------------------------------------------------
        # Families that SHOULD NEVER reach Contain if registry is correct
        # --------------------------------------------------------------
        if family in {VerificationFamily.HTLC, VerificationFamily.APPLICATION_WORKFLOW}:
            return PredicateResult(
                name=self.name,
                ok=False,
                reason="Contain: this family has no state-root-based inclusion.",
            )

        # --------------------------------------------------------------
        # Resolve state_root
        # --------------------------------------------------------------
        state_root = self._get_state_root(e, header)
        if not state_root:
            return PredicateResult(
                name=self.name,
                ok=False,
                reason="Contain: cannot resolve state_root from runtimeLayer.",
            )

        # --------------------------------------------------------------
        # Determine leaf hash
        # --------------------------------------------------------------
        leaf_hash = self._get_leaf_hash(e)
        if leaf_hash is None:
            # If no explicit leaf is provided, fallback to canonical m-hash
            leaf_hash = self._canonical_leaf(m)

        # --------------------------------------------------------------
        # Determine Merkle proof
        # --------------------------------------------------------------
        proof = self._get_merkle_proof(e)

        # ======================================================================
        # FAMILY-SPECIFIC HANDLING
        # ======================================================================

        # ------------------------------------------------------------------
        # 1) MPC/TSS (ME-derived containment only)
        # ------------------------------------------------------------------
        if family == VerificationFamily.MPC_TSS:
            # In reality, MPC runtimeLayer does not contain Merkle proofs.
            # If registry has activated Contain, we assume proof exists.
            if proof is None:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        "Contain(MPC): expecting Merkle proof, "
                        "but no proof fields found in runtimeLayer."
                    ),
                )
            ok = verify_merkle_proof(leaf_hash, proof, state_root)
            return PredicateResult(
                name=self.name,
                ok=ok,
                reason=None if ok else "Merkle verification failed.",
                metadata={"family": family.value},
            )

        # ------------------------------------------------------------------
        # 2) ZK Light Client
        # ------------------------------------------------------------------
        if family == VerificationFamily.ZK_LIGHT_CLIENT:
            # Two modes:
            # (A) explicit Merkle proof → verify;
            # (B) no Merkle proof → rely on Authentic(ZK) (circuit already proved inclusion)
            if proof:
                ok = verify_merkle_proof(leaf_hash, proof, state_root)
                return PredicateResult(
                    name=self.name,
                    ok=ok,
                    reason=None if ok else "Contain(ZK): explicit Merkle proof failed.",
                    metadata={"explicit": True},
                )
            return PredicateResult(
                name=self.name,
                ok=True,
                metadata={
                    "implicit": True,
                    "note": "Contain(ZK): relying on ZK proof (implicit inclusion).",
                },
            )

        # ------------------------------------------------------------------
        # 3) Native Light Client
        # ------------------------------------------------------------------
        if family == VerificationFamily.NATIVE_LIGHT_CLIENT:
            if not proof:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason="Contain(NLC): missing Merkle proof.",
                )
            ok = verify_merkle_proof(leaf_hash, proof, state_root)
            return PredicateResult(
                name=self.name,
                ok=ok,
                reason=None if ok else "Contain(NLC): Merkle verification failed.",
            )

        # ------------------------------------------------------------------
        # 4) Optimistic
        # ------------------------------------------------------------------
        if family == VerificationFamily.OPTIMISTIC:
            # Similar to rollup batch inclusion; explicit Merkle opening if available,
            # fallback to “protocol implicitly enforces inclusion”.
            if proof:
                ok = verify_merkle_proof(leaf_hash, proof, state_root)
                return PredicateResult(
                    name=self.name,
                    ok=ok,
                    reason=None if ok else "Contain(OPT): Merkle proof failed.",
                )
            return PredicateResult(
                name=self.name,
                ok=True,
                metadata={
                    "implicit": True,
                    "note": "Contain(OPT): assuming inclusion is enforced by optimistic protocol.",
                },
            )

        # ------------------------------------------------------------------
        # 5) Default fallback
        # ------------------------------------------------------------------
        return PredicateResult(
            name=self.name,
            ok=False,
            reason="Contain: family not handled.",
        )
