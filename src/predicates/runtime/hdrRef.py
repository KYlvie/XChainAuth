from core.enums import PredicateName
from predicates.base import PredicateResult, PredicateContext, PredicateLayer, Predicate


class HdrRefPredicate(Predicate):
    """
        HdrRefPredicate

        High-level intent.
        ------------------
        This predicate checks that the evidence e actually carries a *well-formed
        header reference* h_s, and that this header is consistent with the claimed
        source domain of the message m.

        Intuition.
        ----------
        Many cross-chain mechanism families embed, directly or indirectly, a
        reference to a source-chain header in their evidence object e. We denote
        this abstractly by a function HdrRef(e), which should return a header h_s
        if the family uses one, or ⊥ if there is no such notion.
        HdrRefPredicate enforces a minimal sanity condition:
            1) HdrRef(e) must not be ⊥;
            2) the header’s chain_id must match the message’s source chain m.src;
            3) the header’s basic fields must be structurally valid (e.g.,
               non-negative height).

        Scope of responsibility.
        ------------------------
        - This predicate *does*:
            • ensure that evidence e really points to some header h_s;
            • ensure that h_s belongs to the same chain that m claims to
              originate from (chain_id == m.src);
            • perform basic structural sanity checks on h_s (here: height ≥ 0).
        - It deliberately does *not*:
            • verify that h_s is canonical, finalized, or non-equivocated;
            • re-check signatures, difficulty, validator sets, or ZK proofs;
            • reason about time, liveness, or message availability.
          Those aspects are handled by other predicates such as Authentic,
          Final, Timely, Contain, etc.

        Relationship to other predicates.
        ---------------------------------
        HdrRefPredicate is a lightweight “typing + routing” guard on the header
        reference inside e. It ensures that when downstream predicates (Authentic,
        DomainBind, Final) talk about “the header h_s carried in the evidence”,
        there really is such a header, and that it is aligned with m.src at the
        level of chain identifiers and basic structure.
        """
    name = PredicateName.HDR_REF
    layer = PredicateLayer.EVIDENCE
    description = (
        "HdrRef(e) must yield a header h_s that is well-formed and "
        "consistent with the source domain of m."
    )

    def evaluate(self, ctx: PredicateContext) -> PredicateResult:
        h = ctx.e.hdr_ref()

        if h is None:
            return PredicateResult(
                name=self.name,
                ok=False,
                reason="HdrRef: HdrRef(e) = ⊥ (no header in evidence).",
            )

        # the header’s chain_id must match the message’s source chain m.src;
        if h.chain_id != ctx.m.src:
            return PredicateResult(
                name=self.name,
                ok=False,
                reason=(
                    f"HdrRef: header.chain_id={h.chain_id} != m.src={ctx.m.src}."
                ),
            )

        # the header’s basic fields must be structurally valid (e.g.,non-negative height).
        if h.height < 0:
            return PredicateResult(
                name=self.name,
                ok=False,
                reason=f"HdrRef: invalid negative height={h.height}.",
            )

        return PredicateResult(
            name=self.name,
            ok=True,
            metadata={
                "chain_id": h.chain_id,
                "height": h.height,
            },
        )
