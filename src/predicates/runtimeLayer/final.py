# src/predicates/final.py
from __future__ import annotations

from typing import Optional, Dict, Any

from core.enums import PredicateName
from predicates.base import Predicate, PredicateLayer, PredicateContext, PredicateResult
from core.models import Header


class FinalPredicate(Predicate):
    """
    Final(h_s): header-level finality predicate (placeholder implementation).

    Intended semantics (for a full implementation):

      - Given a source header h_s (typically obtained via HdrRef(e)),
        Final(h_s) should capture that, under the *source chain's consensus*,
        this header is effectively irreversible.

      Examples by mechanism / consensus type:

        * PoW chains:
            - h_s has at least k confirmations;
            - the reorg probability beyond depth k is below some target bound.

        * BFT-style chains:
            - h_s is included in a committed / finalized block, with a
              justification or commit quorum (e.g. Tendermint commit,
              GRANDPA justification, HotStuff QC).

        * ZK light clients:
            - A ZK proof attests that h_s belongs to a canonical chain view
              that satisfies the chain's finality rules (as encoded in the circuit).

        * Native light clients:
            - A local light client maintains a view of the canonical chain,
              and h_s is marked as finalized / irreversible in that view.

        * Optimistic mechanisms:
            - Finality is often coupled to a dispute window on a parent chain
              (e.g. L1). Once the window has elapsed without a valid fraud
              proof, the batch / header can be treated as final. In this
              framework, we largely model that dimension via Timely, while
              Final(h_s) would express the underlying chain's finality rules.

        * MPC/TSS notary bridges:
            - The committee *may* internally wait for "enough confirmations",
              but the runtimeLayer exposed to the destination chain does not
              carry a verifiable chain-level finality proof. In our semantics,
              MPC/TSS cannot natively satisfy a strong Final(h_s) predicate.

    CURRENT STATUS:

      - This implementation is a placeholder:
          * It always returns ok=True.
          * It does NOT query StateManager or any light client.
          * It only records whatever header reference is present, if any.
      - This allows experiments to run with Final in the pipeline, while
        making it explicit in metadata that no real finality checks are
        enforced yet.
    """

    name = PredicateName.FINAL
    layer = PredicateLayer.RUNTIME
    description = (
        "Header-level finality predicate. Placeholder: always ok=True; "
        "no consensus finality checks are enforced."
    )

    def evaluate(self, ctx: PredicateContext) -> PredicateResult:
        """
        Placeholder evaluation:

          - Extract a header reference via e.hdr_ref(), if available.
          - Always return ok=True.
          - Annotate metadata with family, and (chain_id, height) if a header
            is present.
          - Explicitly state that Final(h_s) is NOT implemented yet.
        """
        header: Optional[Header] = ctx.e.hdr_ref()

        if header is None:
            # Evidence does not even expose a header. We still return ok=True
            # to avoid breaking the pipeline, but clearly signal that Final
            # is not meaningful here.
            return PredicateResult(
                name=self.name,
                ok=True,
                reason=(
                    "Final predicate is a placeholder; runtimeLayer does not expose "
                    "a header (HdrRef(e) = ⊥), so no finality checks are applied."
                ),
                metadata={
                    "family": ctx.family.value,
                    "note": (
                        "Final(h_s) currently not implemented. "
                        "A complete implementation would require a verifiable "
                        "source-chain header and a consensus-specific finality "
                        "check (PoW depth, BFT justification, LC state, etc.)."
                    ),
                },
            )

        # Header is present, but we do not actually check consensus-level finality yet.
        return PredicateResult(
            name=self.name,
            ok=True,
            reason=(
                "Final predicate is a placeholder; header is recorded but no "
                "consensus-level finality checks are enforced."
            ),
            metadata={
                "family": ctx.family.value,
                "chain_id": header.chain_id,
                "height": header.height,
                "hash": header.hash,
                "note": (
                    "Final(h_s) currently always evaluates to True. "
                    "In a full implementation, this would query StateManager "
                    "or a light client / ZK verifier to ensure that this header "
                    "is irreversible under the source chain's consensus."
                ),
            },
        )
