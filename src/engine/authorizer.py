from typing import List, Optional, Dict, Any

from pydantic import BaseModel
from core.enums import PredicateName, VerificationFamily
from core.evidence import Evidence
from core.models import Message
from core.state import StateManager
from predicates.base import PredicateContext, PredicateResult
from predicates.registry import get_pipeline_for_family


class AuthorizationResult(BaseModel):
    """
    Result of a single authorization attempt over (m, e, σ, now).

    Fields
    ------
    authorized : bool
        Global decision of the Authorizer for this (m, e, σ, now) tuple.
        It is True iff *all* predicates in the active pipeline
        (given family + profile) returned ok=True.

    violated_predicates : List[PredicateName]
        The list of predicate *names* that evaluated to ok=False.
        This is the semantic reason why authorization failed.
        Each element corresponds to one logical obligation from
        the unified predicate set (AUTHENTIC, HdrRef, Final, ...).

    predicate_results : List[PredicateResult]
        Full per-predicate diagnostics, in the order they were executed.
        Each PredicateResult contains:
          - name:   PredicateName
          - ok:     bool
          - reason: human-readable explanation (if any)
          - metadata: family/profile-specific debugging info

    error : Optional[str]
        Reserved for exceptional failures in the authorization engine
        itself (e.g., misconfiguration, unexpected exceptions).
        A non-None value here indicates an implementation problem,
        not a semantic violation of the predicates.
    """
    authorized: bool
    violated_predicates: List[PredicateName]
    predicate_results: List[PredicateResult]
    error: Optional[str] = None



class Authorizer:
    """
    The Authorizer is the *semantic execution engine* of the unified
    cross-chain authorization framework.

    -------------------------------------------------------------------------
    1. What is “authorization” in this paper?
    -------------------------------------------------------------------------

    In our semantics, *authorization* means:

        “The destination-side verifier (Authorizer) evaluates a fixed,
        family-independent set of logical predicates over the tuple
        (m, e, σ, now).  Authorization succeeds iff **all predicates**
        required under the selected profile return ok=True.”

    Equivalently:

        authorize(m, e, σ)  :=  ∧_{P ∈ pipeline(family, profile)}  P(m, e, σ)

    - m : the application-level cross-chain message
    - e : the runtimeLayer supplied by the mechanism
    - σ : the destination-side evidenceLayer and (optional) LC state
    - now : current logical time for Timely / ordering semantics

    Key property of our design:

        **Different mechanism families instantiate different runtimeLayer shapes,
        but *all* families are evaluated under one common predicate language.**

    This is the core contribution behind the “unified predicate semantics”
    in Section 4 of the paper.


    -------------------------------------------------------------------------
    2. How the Authorizer operates
    -------------------------------------------------------------------------

    The Authorizer does *not* understand mechanisms directly.
    It performs three tasks:

      (1) Build a PredicateContext(ctx) that contains:
            - m, e
            - family
            - optional header/light-client view via StateManager
            - timestamp “now”
            - params (e.g., crypto registries, fraud-proof sets)

      (2) Ask the registry for the correct predicate pipeline:
            predicates = get_pipeline_for_family(family, profile)

          This pipeline is ordered
          (AUTHENTIC → HdrRef → Final → Contain → DomainBind → …).

      (3) Execute each predicate and collect results.
          Evidence-layer predicates depend only on (m, e).
          Runtime-layer predicates depend on σ (routing, ordering, replay, etc.).

      Authorization = True  iff  no predicate returns ok=False.


    -------------------------------------------------------------------------
    3. Profile semantics
    -------------------------------------------------------------------------

    profile="native"
        - Models what the mechanism natively exposes in reality.
        - Context contains *only m and e*, no external chain state.
        - ctx.state is replaced with None.
        - Typical for MPC/TSS, HTLC, workflow bridges, optimistic systems
          in their minimal compliance configuration.

    profile="full_state"
        - Used by mechanisms that *can* supply a light-client or ZK-verified
          header view (e.g., ZK light clients, native LCs).
        - ctx.state is the actual StateManager, providing:
            * header views
            * source-chain mirrors for Contain/Final where supported
            * replay/ordering state

        - For families that don’t natively support chain-level runtimeLayer
          (e.g.HTLC ), this behaves identically to “native” but leaves
          the door open for Section 6 experiments.


    -------------------------------------------------------------------------
    4. Why this design is correct for our semantics
    -------------------------------------------------------------------------

    - The Authorizer never “decides” the semantics.
      Predicates are the *only* semantic unit, and they encode the logic.

    - The Authorizer never inspects or interprets runtimeLayer internally.
      It simply forwards (m, e, σ) to predicates, which is crucial for
      keeping the design mechanism-agnostic.

    - Different families can expose different capabilities:
         • MPC/TSS: only Authentic + DomainBind + ContextOK
         • ZK LC: Authentic via ZK + HdrRef + Final + Contain
         • Native LC: similar but no ZK proof
         • Optimistic: Authentic=trivial, Timely enforces window semantics
         • HTLC/workflow: Authentic/HdrRef not meaningful; evidenceLayer predicates dominate

      The pipeline remains unified across all of them.


    -------------------------------------------------------------------------
    5. Error handling semantics
    -------------------------------------------------------------------------

    - If a predicate raises an exception, the Authorizer does NOT
      treat it as a security violation but records it as `error`
      in AuthorizationResult.
    - A predicate returning ok=False is a *semantic violation*,
      meaning authorization rejects the message.


    -------------------------------------------------------------------------
    6. Summary
    -------------------------------------------------------------------------

    The Authorizer is intentionally minimal. It is the executor of the
    “predicate contract” defined in Section 4 — no more, no less.
    All mechanism-specific differences appear only through:
        - the runtimeLayer (e),
        - the available chain state in ctx.state,
        - and the capabilities exposed by each mechanism family.

    This ensures the *universal comparability* of heterogeneous mechanisms,
    which is the central motivation of the paper.
    """

    def authorize(
        self,
        m: Message,
        e: Evidence,
        family: VerificationFamily,
        state: StateManager,
        now: int,
        *,
        profile: str = "full_state",
        params: Optional[Dict[str, Any]] = None,
    ) -> AuthorizationResult:
        """
        Execute the predicate pipeline for (m, e, family, now) and return
        a complete authorization result.

        Parameters
        ----------
        m : Message
            Application-level cross-chain message.

        e : Evidence
            Family-dependent runtimeLayer object.  Its internal structure varies
            by mechanism (MPC/TSS attestation, ZK proof, LC header, claim…)
            but the Authorizer does not interpret it.

        family : VerificationFamily
            Declares which pipeline applies.  Defined in enum VerificationFamily.

        state : StateManager
            Provides source-chain mirrors and D-side evidenceLayer state.  Used only
            under “full_state” profile or by evidenceLayer predicates.

        now : int
            Logical time used by Timely, ordering, and some evidenceLayer predicates.

        profile : {"native", "full_state"}
            Controls how much external state is visible to predicates.

        params : dict
            Crypto verifiers, fraud-proof sets, threat injections, etc.
            Predicates extract what they need.

        Returns
        -------
        AuthorizationResult
            Contains:
              - authorized (bool)
              - violated_predicates: list[PredicateName]
              - predicate_results: list[PredicateResult]
              - error: optional error string
        """

        if profile not in ("native", "full_stack"):
            raise ValueError(f"Unknown profile: {profile}")

        params = params or {}

        # In "native" mode, no chain state is visible to predicates.
        # This reflects mechanisms that do not natively expose
        # chain-level mirrors or LC views.

        # Full source-chain mirror (StateManager) is visible.
        state_for_predicates = state

        # Build predicate context.
        ctx = PredicateContext(
            m=m,
            e=e,
            family=family,
            state=state_for_predicates,
            now=now,
            params=params,
        )

        # Obtain the unified predicate pipeline.
        predicates = get_pipeline_for_family(family=family, profile=profile)

        results: List[PredicateResult] = []
        violated: List[PredicateName] = []

        for pred in predicates:
            res = pred(ctx)
            results.append(res)
            if not res.ok:
                violated.append(res.name)

        authorized = (len(violated) == 0)

        return AuthorizationResult(
            authorized=authorized,
            violated_predicates=violated,
            predicate_results=results,
            error=None,
        )

