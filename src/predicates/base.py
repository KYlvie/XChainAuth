# src/predicates/base.py
from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from core.enums import PredicateName, VerificationFamily
from core.models import Message
from core.evidence import Evidence
from core.state import StateManager


JsonDict = Dict[str, Any]


class PredicateLayer(str, Enum):
    """
    Logical layer of a predicate.

    We conceptually separate predicates into two layers:

      * EVIDENCE:
          Predicates that only inspect the evidence object `e` and
          information that is directly bound to it (e.g. headers,
          signatures, ZK proofs, committee attestations).

      * RUNTIME:
          Predicates that additionally depend on mutable runtime state σ
          on the destination chain (managed by StateManager). Examples:
          replay protection, ordering, domain policy, time windows.

    This enum is purely for documentation / debugging. It does not
    enforce any behavior by itself.
    """

    EVIDENCE = "evidence"
    RUNTIME = "runtime"


class PredicateContext(BaseModel):
    """
    Unified input context passed to every predicate.

    It corresponds to the abstract setting in the paper:

      * m: Application-level message that claims to originate from S.
      * e: Evidence object intended to support authorization of m.
      * family: Verification family that produced e (MPC, ZK LC, etc.).
      * state: Destination-side state manager σ, which exposes:
          - header / finality views (for families that have them);
          - replay / inflight / ordering state on D;
          - policy configuration (allowed routes, etc.).
      * now: Current time (logical or wall-clock) used by Timely and
        other time-based predicates.
      * params: Free-form parameter bag for experiment knobs or
        implementation-specific configuration (e.g., max_age).

    The Authorizer is responsible for constructing this context before
    calling any predicates.
    """

    m: Message = Field(
        ...,
        description="Application-level cross-chain message to be authorized.",
    )

    e: Evidence = Field(
        ...,
        description="Evidence object that justifies, or claims to justify, m.",
    )

    family: VerificationFamily = Field(
        ...,
        description="Verification family that this (m, e) pair belongs to.",
    )

    # Runtime environment: may be None if a test runs purely
    # evidence-layer predicates without any σ-based checks.
    state: Optional[StateManager] = Field(
        ...,
        description=(
            "Destination-side state manager σ, used by runtime predicates "
            "to access finality, replay, ordering, and policy information."
        ),
    )

    # Logical "now" (e.g., block timestamp or experiment time).
    now: Optional[int] = Field(
        default=None,
        description="Current logical or wall-clock time, used by Timely, etc.",
    )

    # Free-form configuration and experimental knobs.
    params: JsonDict = Field(
        default_factory=dict,
        description=(
            "Optional predicate configuration / parameters. "
            "Typical usage: max_age, family-specific thresholds, debug flags."
        ),
    )

    class Config:
        # We allow arbitrary Python types here (e.g., concrete StateManager
        # implementations, crypto helpers) without forcing them to be
        # pydantic models.
        arbitrary_types_allowed = True


class PredicateResult(BaseModel):
    """
    Result of evaluating a single predicate on a given context.

    Fields:
      * name:
          Which predicate was evaluated (PredicateName).
      * ok:
          Boolean outcome:
            - True  → predicate is satisfied under the current context.
            - False → predicate is violated (or, in some designs, the
              property is pending and cannot yet be considered satisfied).
      * reason:
          Human-readable explanation of why the predicate failed or, if
          needed, what exactly was checked. Intended primarily for logs
          and debugging output.
      * metadata:
          Structured auxiliary data that may be useful for analysis and
          experiments (e.g., heights, timestamps, sequence numbers,
          pending/expired flags, fraud_proof indicators, etc.).
    """

    name: PredicateName
    ok: bool
    reason: Optional[str] = None
    metadata: JsonDict = Field(default_factory=dict)


class Predicate(ABC):
    """
    Abstract base class for all concrete predicates
    (Authentic, HdrRef, Final, Contain, DomainBind, Timely, Unique, ...).

    Each concrete predicate must:

      * Set:
          - `name`:     a PredicateName enum member.
          - `layer`:    PredicateLayer.EVIDENCE or PredicateLayer.RUNTIME.
          - `description`: short textual description (optional but
            strongly recommended).
          - `families_applicable` (optional): if not None, restricts
            the predicate to only those verification families.

      * Implement:
          - `evaluate(self, ctx: PredicateContext) -> PredicateResult`
            where the semantics of the predicate are enforced.
    """

    # Concrete subclasses must override these attributes.
    name: PredicateName
    layer: PredicateLayer
    description: str = ""

    # If a predicate only makes sense for some families, this set can be
    # populated. If None, the predicate is considered *conceptually* applicable
    # to all families, and the internal logic decides what to do.
    #
    # Note: In the current design, we usually control applicability via
    # the pipeline selection (registry + profile), so this field is mainly
    # documentation / an optional extra safeguard.
    families_applicable: Optional[set[VerificationFamily]] = None

    def __call__(self, ctx: PredicateContext) -> PredicateResult:
        """
        Allow predicates to be called like functions: pred(ctx).

        This simply delegates to `evaluate`. The Authorizer and tests use
        this for a clean, uniform invocation style.
        """
        return self.evaluate(ctx)

    def is_applicable_to(self, family: VerificationFamily) -> bool:
        """
        Return True if this predicate is conceptually applicable to the
        given verification family.

        If `families_applicable` is None, the predicate is treated as
        applicable to all families. Otherwise, it must appear in the set.
        """
        if self.families_applicable is None:
            return True
        return family in self.families_applicable

    @abstractmethod
    def evaluate(self, ctx: PredicateContext) -> PredicateResult:
        """
        Core predicate logic.

        Implementations should:
          * Read only from `ctx` (m, e, family, state, now, params).
          * Avoid side effects on shared state (only StateManager is
            allowed to mutate σ, and that is typically done by
            mechanisms or explicit state-update procedures, not by
            predicates themselves).
          * Return a fully populated PredicateResult with:
              - name set to `self.name`,
              - ok set according to the predicate semantics,
              - reason and metadata filled in enough to support debugging
                and later analysis in experiments.
        """
        raise NotImplementedError
