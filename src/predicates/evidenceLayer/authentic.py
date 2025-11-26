from typing import Optional

from core.enums import PredicateName, VerificationFamily
from core.evidence import MPCEvidence, ZKLightClientEvidence, NativeLightClientEvidence, OptimisticEvidence
from helper.crypto import CommitteeVerifierRegistry, GlobalZkVerifier, OptimisticVerifier
from predicates.base import Predicate, PredicateLayer, PredicateContext, PredicateResult


class AuthenticPredicate(Predicate):
    """
        AuthenticPredicate

        High-level intent.
        ------------------
        This predicate is the family-native *cryptographic authenticity* check for
        a single (message, runtimeLayer) pair (m, e). Given a PredicateContext ctx, it
        decides whether the runtimeLayer object e is a valid, family-specific proof
        that “someone trustworthy really attested to the claimed source-chain
        state or message”.

        Scope of responsibility.
        ------------------------
        - Focuses ONLY on the authenticity of e:
            • Is the committee threshold signature valid? (MPC_TSS)
            • Does the ZK proof verify under the global verifier key? (ZK_LIGHT_CLIENT)
            • Is the claimed header consistent with the simulated light client
              view of the source chain? (NATIVE_LIGHT_CLIENT)
            • Is the optimistic commitment correctly signed by the aggregator?
              (OPTIMISTIC)
        - It deliberately does NOT decide:
            • whether the source state is final or could still be reverted;
            • whether m is correctly bound to the right domain / route;
            • whether the runtimeLayer is fresh enough or within a time bound;
            • whether the message is still “live” in the application workflow.
          Those concerns are handled by other predicates such as Final, DomainBind,
          Timely, Contain, etc.

        Multi-family dispatch.
        ----------------------
        The implementation uses ctx.family to dispatch into different
        family-specific branches:
            - VerificationFamily.MPC_TSS:
                checks committee registration and threshold signature via a
                CommitteeVerifierRegistry supplied in ctx.params.
            - VerificationFamily.ZK_LIGHT_CLIENT:
                calls GlobalZkVerifier on (proof, public_inputs).
            - VerificationFamily.NATIVE_LIGHT_CLIENT:
                compares the header carried in the runtimeLayer against a canonical
                header returned by ctx.state.get_header_view(...).
            - VerificationFamily.OPTIMISTIC:
                checks that an aggregator signature over a commitment is valid
                using OptimisticVerifier.

        For mechanism families that do not expose a meaningful cross-chain
        cryptographic runtimeLayer object (e.g., HTLC or pure application workflows),
        AuthenticPredicate currently acts as a no-op and returns ok=True, with the
        understanding that their safety is enforced by evidenceLayer predicates and the
        end-to-end protocol design rather than by a standalone Authentic(e) check.
        """
    name = PredicateName.AUTHENTIC
    layer = PredicateLayer.EVIDENCE
    description = "Family-native cryptographic verification of runtimeLayer e."

    def evaluate(self, ctx: PredicateContext) -> PredicateResult:
        family = ctx.family

        # ------------------------------------------------------------------
        # 1) MPC_TSS (committee-based notary):
        #    - Real-world semantics:
        #      A committee (MPC/TSS signers) observes the source chain and
        #      produces a threshold signature over a tuple (m, hs), where hs
        #      is a claimed source-chain header or state snapshot. The
        #      authorizer on D does *not* re-execute the consensus rules of S;
        #      it only checks that:
        #        (a) there exists a registered verifier for this committee_id;
        #        (b) the committee’s threshold signature over (m, hs) is valid.
        #      Authenticity is therefore reduced to the honesty and key
        #      security of the committee, plus correct configuration of
        #      committee_verifiers on D.
        #
        #    - Experimental semantics in this predicate:
        #      We treat ctx.params["committee_verifiers"] as a registry that
        #      maps committee_id -> CommitteeVerifier instance. For the given
        #      MPCEvidence e, we extract:
        #        - hdr_ref(e)  : the claimed source header hs;
        #        - attestation : the committee’s signature object.
        #      Authentic(MPC) returns ok iff:
        #        1) hdr_ref(e) is present (not ⊥);
        #        2) there is a verifier registered for att.committee_id; and
        #        3) verifier.verify_attestation(ctx.m, hs, att) returns True.
        #      We do *not* in this predicate check reorg-depth, finality, or
        #      domain binding; those belong to other predicates such as Final
        #      and DomainBind.
        # ------------------------------------------------------------------

        if family == VerificationFamily.MPC_TSS:
            assert isinstance(ctx.e, MPCEvidence)
            e = ctx.e

            header = e.hdr_ref()
            if header is None:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason="Authentic(MPC): HdrRef(e) = ⊥, no header in runtimeLayer.",
                )

            registry: Optional[CommitteeVerifierRegistry] = ctx.params.get(
                "committee_verifiers"  # type: ignore[arg-type]
            )
            if registry is None:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason="Authentic(MPC): missing ctx.params['committee_verifiers'].",
                )

            att = e.attestation
            verifier = registry.get(att.committee_id)
            if verifier is None:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        "Authentic(MPC): no verifier for "
                        f"committee_id={att.committee_id}."
                    ),
                )

            ok = verifier.verify_attestation(ctx.m, header, att)
            if not ok:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason="Authentic(MPC): committee attestation failed.",
                )

            return PredicateResult(
                name=self.name,
                ok=True,
                metadata={
                    "family": family.value,
                    "committee_id": att.committee_id,
                },
            )

        # ------------------------------------------------------------------
        # 2) ZK light client:
        #    - Real-world semantics:
        #      A ZK light client embeds the consensus rules of the source
        #      chain S into a succinct proof system. The relayer submits
        #      a proof π and public inputs x that jointly assert:
        #         “According to S’s rules, header hs (and optionally some
        #          application-level facts) is valid and consistent.”
        #      On the destination chain D, a verifier contract or module
        #      checks π against x using a fixed verification key. If the
        #      proof is accepted, D implicitly trusts that hs (and the
        #      claimed facts) are consistent with the canonical state of S,
        #      up to the assumptions of the ZK system and the circuit.
        #
        #    - Experimental semantics in this predicate:
        #      We model the on-chain verifier as a single module
        #      GlobalZkVerifier. The ZKLightClientEvidence e contains:
        #        - e.proof          : the succinct proof π;
        #        - e.public_inputs  : the public inputs x (encoding header
        #                             data, state roots, etc.).
        #      Authentic(ZK) returns ok iff GlobalZkVerifier.verify(π, x)
        #      succeeds. We do not inspect the structure of x or the exact
        #      circuit; we treat the verifier as an opaque, family-native
        #      cryptographic checker. Finality, freshness, and routing are
        #      handled by other predicates, not by Authentic itself.
        # ------------------------------------------------------------------
        if family == VerificationFamily.ZK_LIGHT_CLIENT:
            assert isinstance(ctx.e, ZKLightClientEvidence)
            e = ctx.e

            ok = GlobalZkVerifier.verify(e.proof, e.public_inputs)
            if not ok:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason="Authentic(ZK): GlobalZkVerifier rejected proof.",
                )

            return PredicateResult(
                name=self.name,
                ok=True,
                metadata={
                    "family": family.value,
                    "note": "Proof accepted by global ZK verifier module.",
                },
            )

        # ------------------------------------------------------------------
        # 3) Native light client:
        #    - Real-world semantics:
        #      A native light client on D maintains an internal view of S by
        #      incrementally verifying headers using S’s native consensus
        #      rules (e.g., validator signatures for BFT, PoW difficulty and
        #      chain work for Nakamoto consensus, validator set updates, etc.).
        #      Once a header hs is accepted by the light client, application
        #      contracts on D can treat hs as a trusted anchor for state
        #      commitments (state_root, receipts_root, etc.).
        #
        #    - Experimental semantics in this predicate:
        #      Instead of embedding a full light client, we give the
        #      StateManager a method get_header_view(chain_id, height) that
        #      returns the canonical header from a simulated chain view, or
        #      None if no such header exists. NativeLightClientEvidence e
        #      carries a claimed header hs_e that is supposed to match this
        #      canonical view.
        #
        #      Authentic(NLC) returns ok iff:
        #        1) e.header is not None;
        #        2) the chain view contains a canonical header hs_chain at
        #           (chain_id, height) = (hs_e.chain_id, hs_e.height);
        #        3) where available, key commitment fields (hash, state_root,
        #           etc.) of hs_e and hs_chain agree.
        #      We deliberately *do not* encode finality depth, fork-choice, or
        #      time-related properties here; those are the responsibility of
        #      predicates such as Final and Timely. Authentic(NLC) focuses
        #      only on consistency between the runtimeLayer header and the
        #      simulated chain view.
        # ------------------------------------------------------------------

        if family == VerificationFamily.NATIVE_LIGHT_CLIENT:
            assert isinstance(ctx.e, NativeLightClientEvidence)
            e = ctx.e
            hs_e = e.header  # from runtimeLayer claimed header

            if hs_e is None:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason="Authentic(NLC): runtimeLayer.header is None.",
                )

            # Here we assume that StateManager provides a method get_header_view(chain_id, height)
            # which returns the canonical header from the chain's simulated view (or None if not found).
            try:
                hs_chain = ctx.state.get_header_view(hs_e.chain_id, hs_e.height)  # type: ignore[attr-defined]
            except AttributeError:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        "Authentic(NLC): StateManager has no get_header_view(...); "
                        "please add it to your experimental state implementation."
                    ),
                )

            if hs_chain is None:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        "Authentic(NLC): no canonical header found in chain view "
                        f"for (chain_id={hs_e.chain_id}, height={hs_e.height})."
                    ),
                    metadata={
                        "chain_id": hs_e.chain_id,
                        "height": hs_e.height,
                    },
                )

            # Compare commitment fields such as hash / state_root whenever possible
            if (
                    hs_chain.hash is not None
                    and hs_e.hash is not None
                    and hs_chain.hash != hs_e.hash
            ):
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason="Authentic(NLC): header.hash mismatch with chain view.",
                    metadata={
                        "claimed_hash": hs_e.hash,
                        "chain_hash": hs_chain.hash,
                    },
                )

            if (
                    hs_chain.state_root is not None
                    and hs_e.state_root is not None
                    and hs_chain.state_root != hs_e.state_root
            ):
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason="Authentic(NLC): header.state_root mismatch with chain view.",
                    metadata={
                        "claimed_root": hs_e.state_root,
                        "chain_root": hs_chain.state_root,
                    },
                )

            return PredicateResult(
                name=self.name,
                ok=True,
                metadata={
                    "family": family.value,
                    "chain_id": hs_e.chain_id,
                    "height": hs_e.height,
                    "note": "Native LC: header consistent with simulated chain view.",
                },
            )

        # ------------------------------------------------------------------
        # 4) Optimistic verification:
        #    - Real-world semantics:
        #      In optimistic schemes, an off-chain aggregator (or a set of
        #      relayers) posts a commitment to some source-chain state (e.g.,
        #      a header hash or state_root) on the destination chain D,
        #      usually as:
        #        commitment := Commit(hs, aux_data)
        #      together with a signature or authentication tag. The commitment
        #      is tentatively trusted unless a challenger submits a valid
        #      fraud proof within a challenge window. If no challenge arrives,
        #      the commitment is treated as correct and used for authorization.
        #
        #    - Experimental semantics in this predicate:
        #      We restrict Authentic(OPT) to *pure signature validity* over
        #      the commitment, abstracting away the full challenge/counter-
        #      challenge protocol. OptimisticEvidence e is assumed to carry:
        #        - e.commitment : an opaque commitment value;
        #        - e.signature  : an authenticator from the aggregator.
        #      OptimisticVerifier models the verification logic that would be
        #      embedded in an on-chain verifier contract on D.
        #
        #      Authentic(OPT) returns ok iff:
        #        1) e.commitment and e.signature are both present; and
        #        2) OptimisticVerifier.verify_commitment(commitment, signature)
        #           accepts.
        #      We intentionally do *not* encode timeout logic or liveness of
        #      the challenge process here; such temporal and finality aspects
        #      belong to Timely, Final, or other higher-level predicates.
        # ------------------------------------------------------------------

        if family == VerificationFamily.OPTIMISTIC:
            assert isinstance(ctx.e, OptimisticEvidence)
            e = ctx.e

            # We assume that OptimisticEvidence contains at least:
            #   - commitment: a commitment to a header or state_root (bytes or str);
            #   - signature: the aggregator’s signature over the commitment.
            commitment = getattr(e, "commitment", None)
            signature = getattr(e, "signature", None)

            if commitment is None or signature is None:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        "Authentic(OPT): runtimeLayer missing commitment and/or signature."
                    ),
                )

            # OptimisticVerifier emulates the “hard-coded on-chain verifier contract”
            # used in real optimistic mechanisms.
            # A simple version (based on HMAC) is implemented in helper.crypto.
            if not OptimisticVerifier.verify_commitment(commitment, signature):
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason="Authentic(OPT): aggregator signature over commitment invalid.",
                )

            return PredicateResult(
                name=self.name,
                ok=True,
                metadata={
                    "family": family.value,
                    "note": "Optimistic: commitment accepted by OptimisticVerifier.",
                },
            )
        # ------------------------------------------------------------------
        # 5) Other families (evidenceLayer-only or not implemented):
        #    For families that do not have a meaningful cryptographic
        #    cross-chain runtimeLayer object (e.g., pure HTLC-style workflows or
        #    application-layer protocols without a dedicated header+proof
        #    structure), Authentic is treated as a no-op: we return ok=True
        #    and delegate all safety obligations to other predicates.
        #
        #    Typical examples include:
        #      - HTLC: correctness depends on hash preimage secrecy and the
        #        atomicity of contract workflows across chains, rather than
        #        a standalone “runtimeLayer” object that can be verified in
        #        isolation.
        #      - APPLICATION_WORKFLOW: cross-chain semantics are enforced by
        #        coordinated application logic, off-chain relayers, and local
        #        checks on each chain, again without an independent runtimeLayer
        #        artifact.
        #
        #    In such families, security properties like atomicity,
        #    containment, and liveness are captured by evidenceLayer predicates
        #    (Contain, Timely, etc.) and by the end-to-end protocol design,
        #    not by a family-native Authentic(e) checker.
        # ------------------------------------------------------------------

        return PredicateResult(
            name=self.name,
            ok=True,
            metadata={
                "family": family.value,
                "note": "Authentic not specifically implemented for this family.",
            },
        )


