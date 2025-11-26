from __future__ import annotations
from core.enums import PredicateName, VerificationFamily
from predicates.base import Predicate
from predicates.evidence.contain import ContainPredicate
from predicates.evidence.domainOK import DomainOKPredicate
from predicates.evidence.final import FinalPredicate
from predicates.evidence.order import OrderPredicate
from predicates.evidence.timely import TimelyPredicate
from predicates.evidence.unique import UniquePredicate
from predicates.runtime.authentic import AuthenticPredicate
from predicates.runtime.contextOK import ContextOKPredicate
from predicates.runtime.domainBind import DomainBindPredicate
from predicates.runtime.hdrRef import HdrRefPredicate
"""
Predicate registry and capability matrix.

This module serves two related but conceptually distinct purposes:

1)  Predicate instantiation
    ------------------------
    It maps each PredicateName to a concrete Predicate implementation
    class (REAL_PREDICATE_CLASSES), and exposes a helper
    `get_pipeline_for_family(...)` that returns a list of Predicate
    instances to be executed as an authorization pipeline.

2)  Capability description (per mechanism family)
    ---------------------------------------------
    It records, for each VerificationFamily, which predicates are
    *natively* supported (at least partially) by real-world instances
    of that family. Here “has capability” means:

        - The family as deployed in practice *already implements* that
          predicate’s semantics (or a close variant), at least partially
          and on the critical path for safety; OR
        - It can do so with straightforward configuration (e.g., a
          policy table) without changing the fundamental mechanism.

    In other words, we deliberately count *partial* native support as
    “has capability” for the purposes of the capability matrix. Predicates
    that require a semantic hardening or architectural change are
    considered “no native capability”.

The actual experimental pipelines are controlled by the `profile`
argument in `get_pipeline_for_family`:

    - profile="native":
        Run only those predicates for which the given family has some
        native capability (according to the matrix below).
    - profile="full_stack":
        Run the full conceptual stack of ten predicates
        (evidence layer + runtime layer), in their canonical
        order, regardless of whether the family has native support.
        This is useful for “hardened semantics” experiments.

        If some predicates do not yet have a concrete implementation
        class, they are silently skipped at instantiation time; once you
        add their classes to REAL_PREDICATE_CLASSES, they will be pulled
        into the pipelines automatically.
"""

from typing import Dict, Type, List
from core.enums import PredicateName, VerificationFamily
from predicates.base import Predicate



# ================================================================
# 1) PredicateName -> concrete implementation class
#    Only predicates that already have a Python implementation
#    should be registered here.
# ================================================================

REAL_PREDICATE_CLASSES: Dict[PredicateName, Type[Predicate]] = {
    PredicateName.AUTHENTIC:   AuthenticPredicate,
    PredicateName.HDR_REF:     HdrRefPredicate,
    PredicateName.CONTEXT_OK:  ContextOKPredicate,
    PredicateName.DOMAIN_BIND: DomainBindPredicate,
    PredicateName.CONTAIN:     ContainPredicate,
    PredicateName.FINAL:       FinalPredicate,
    PredicateName.UNIQUE:      UniquePredicate,
    PredicateName.DOMAIN_OK:   DomainOKPredicate,
    PredicateName.TIMELY:      TimelyPredicate,
    PredicateName.ORDER:       OrderPredicate,

}


def _make_pred(name: PredicateName) -> Predicate:
    """
    Instantiate a predicate by name.

    NOTE:
        We assume that only predicates present in REAL_PREDICATE_CLASSES
        will ever be instantiated. The pipeline construction logic below
        filters out names that have no registered implementation
    """
    cls = REAL_PREDICATE_CLASSES[name]
    return cls()


# ================================================================
# 2) Canonical predicate order
#    This gives a single, canonical ordering of the ten predicates:
#    first the evidence-layer, then the runtime layer.
# ================================================================

CANONICAL_ORDER: List[PredicateName] = [
    # Evidence layer (attestation / commitment surface)
    PredicateName.HDR_REF,       # HdrRef(e)
    PredicateName.AUTHENTIC,     # Authentic(e)
    PredicateName.DOMAIN_BIND,   # DomainBind(m, e)
    PredicateName.CONTEXT_OK,    # ContextOK(e)

    # State / time / policy layer (destination validation)
    PredicateName.CONTAIN,       # Contain(m, h_s)
    PredicateName.FINAL,         # Final(h_s)
    PredicateName.DOMAIN_OK,     # DomainOK(m)
    PredicateName.UNIQUE,        # Unique(m)
    PredicateName.TIMELY,        # Timely(m)
    PredicateName.ORDER,         # Order(m)

]


# ================================================================
# 3) Capability matrix:
#    For each verification family, record which predicates it
#    *natively* supports (at least partially) in real deployments.
#
#    Interpretation:
#      - If a predicate appears in the list for a family, that family
#        “has capability” for that predicate (possibly partial).
#      - If it does not appear, that predicate requires a semantic
#        hardening or architectural change to be realized.
#
#    This matrix is based on the analysis of deployed bridges:
#      - MPC/TSS notary schemes
#      - optimistic rollups/bridges
#      - ZK light-client based bridges
#      - native light-client protocols (IBC-style)
#      - HTLC-based schemes
#      - application-layer workflows
# ================================================================

FAMILY_NATIVE_CAPABILITIES: Dict[VerificationFamily, List[PredicateName]] = {
    # ------------------------------------------------------------
    # ZK light-client family
    # ------------------------------------------------------------
    # ZK light clients can, in principle and often in practice, support
    # the full stack of predicates:
    #   - Authentic(e): zk proof verification
    #   - HdrRef(e):    header / state_root encoded in public_inputs
    #   - DomainBind:   chainId / route / appId baked into public_inputs
    #   - ContextOK:    circuit_id / vk_id / schema version / domain tags
    #   - Contain:      Merkle inclusion or inbox-root opening proven in-circuit
    #   - Final:        finalized checkpoint or depth proven in-circuit
    #   - Unique:       anti-replay via message-id tracking on the destination
    #   - Timely:       TTL / freshness constraints
    #   - Order:        per-channel sequence enforced against stored state
    #   - DomainOK:     routing policy based on (src, dst, chan, appId, …)
    VerificationFamily.ZK_LIGHT_CLIENT: list(CANONICAL_ORDER),

    # ------------------------------------------------------------
    # Native light-client family (e.g., IBC-like protocols)
    # ------------------------------------------------------------
    # Native LCs also naturally realize almost all predicates:
    #   - Authentic(e): light-client verification rules (BFT commit, PoW depth, …)
    #   - HdrRef(e):    the LC state *is* a header store; references are explicit
    #   - DomainBind:   client/connection/channel/port binding provides route binding
    #   - ContextOK:    client type & version, key-epoch, schema state
    #   - Contain:      Merkle proofs against LC-maintained roots (ICS-23 style)
    #   - Final:        finalized header set, trusting period, depth thresholds
    #   - Unique:       channel-level recv/ack state tracks message consumption
    #   - Timely:       timeout_height / timeout_timestamp + LC time model
    #   - Order:        ORDERED channels enforce FIFO per route
    #   - DomainOK:     high-level routing policy via configured clients/channels
    VerificationFamily.NATIVE_LIGHT_CLIENT: list(CANONICAL_ORDER),

    # ------------------------------------------------------------
    # MPC/TSS notary family
    # ------------------------------------------------------------
    # MPC/TSS bridges typically provide:
    #   - Authentic(e): committee signature verification is native.
    #   - HdrRef(e):    header hash / height often appear in the signed tuple,
    #                   but the destination chain does not replay S's consensus.
    #   - DomainOK(m,e): sometimes realized via “trusted remote” mappings
    #                   (e.g., per-src-chain or per-src-address allow-lists).
    #
    # They *do not* natively provide:
    #   - DomainBind(m,e): route tuple equality is rarely enforced in the
    #     signed payload.
    #   - ContextOK(e): key-epoch/schema/TTL/nonce are not systematically
    #     encoded.
    #   - Contain/Final: no header-level Merkle or finality checking.
    #   - Unique/Timely/Order: left to application logic if present at all.
    VerificationFamily.MPC_TSS: [
        PredicateName.AUTHENTIC,
        PredicateName.HDR_REF,
        PredicateName.DOMAIN_OK,
    ],

    # ------------------------------------------------------------
    # Optimistic verification family (rollups / optimistic bridges)
    # ------------------------------------------------------------
    # Optimistic mechanisms usually provide:
    #   - Authentic(e): proposer / aggregator signature over a claim
    #   - HdrRef(e):    state_root / L2 block index committed to L1
    #   - ContextOK(e): rollupId / chainId / batchIndex, etc. act as
    #                   a partial schema/key-epoch context.
    #   - Contain(m,hs): some designs prove or at least index inclusion
    #                    of messages in batches (though often at batch
    #                    granularity rather than per-message).
    #   - Timely(m,e):   the dispute window is a native timeliness guard.
    #   - DomainOK(m,e): coarse-grained chain-pair binding (this L1
    #                    contract is “the canonical bridge for L2 X”).
    VerificationFamily.OPTIMISTIC: [
        PredicateName.AUTHENTIC,
        PredicateName.HDR_REF,
        PredicateName.CONTEXT_OK,
        PredicateName.CONTAIN,
        PredicateName.TIMELY,
        PredicateName.DOMAIN_OK,
    ],

    # ------------------------------------------------------------
    # HTLC family (hash time-locked contracts)
    # ------------------------------------------------------------
    # HTLCs do *not* provide evidence-layer predicates: there is no
    # cross-chain header evidence, only local contracts on A and B.
    #
    # Runtime-layer:
    #   - Unique(m):  the hash_lock effectively acts as a one-time token;
    #                 once the preimage has been used, the same hash usually
    #                 cannot be reused safely.
    #   - Timely(m):  timelock is native.
    #
    # There is generally no canonical Final/Contain/Order/DomainOK unless
    # enforced by higher-level protocols.
    VerificationFamily.HTLC: [
        PredicateName.UNIQUE,
        PredicateName.TIMELY,
    ],

    # ------------------------------------------------------------
    # Application-layer workflow family
    # ------------------------------------------------------------
    # For generic application workflows, there is no standardized evidence
    # object; all safety properties live in the application state machine.
    #
    # In principle, many runtime-layer predicates can be realized:
    #   - Unique(m):   via a seen(messageId) mapping.
    #   - Timely(m,e): via application-level TTL / expiry rules.
    #   - Order(m):    via workflow steps or per-channel sequence.
    #   - DomainOK(m,e): via explicit routing policies in the app contract.
    #
    # But these are purely application-specific; we mark Order and DomainOK
    # as “has capability” to indicate that the family can support them when
    # designed carefully, not that every workflow automatically does so.
    VerificationFamily.APPLICATION_WORKFLOW: [
        PredicateName.UNIQUE,
        PredicateName.TIMELY,
        PredicateName.ORDER,
        PredicateName.DOMAIN_OK,
    ],
}


# ================================================================
# 4) Profile definitions:
#
#    - "native":
#        Per-family selection. Only run predicates for which the family
#        has some native capability (according to FAMILY_NATIVE_CAPABILITIES),
#        in the canonical ordering from CANONICAL_ORDER.
#
#    - "full_stack":
#        Run the full conceptual stack from Table 4 in canonical order,
#        regardless of native capabilities. This is the default for
#        experiments that want to measure the *hardened* semantics of
#        each family.
#
#        For mechanism families that do not natively expose all fields
#        required by a given predicate (e.g., seq/nonce/channel/TTL for
#        ContextOK, or Merkle paths for Contain, or routing metadata for
#        DomainBind/DomainOK), we *instrument* the model in two ways:
#
#          1) Via StateManager:
#               Missing information that can be reconstructed from a
#               simulated source-chain or destination-chain view is
#               supplied through the StateManager interface
#               (e.g., get_header_view(...), get_message_context(...),
#               lookup_inclusion_proof(...), routing policy tables, etc.).
#
#          2) Via evidence enrichment:
#               When the real protocol could plausibly carry additional
#               context without changing its fundamental architecture,
#               we model a “hardened” version of the family by explicitly
#               adding those fields into the evidence object e
#               (e.g., adding a context map with nonce/seq/channel/TTL,
#               or embedding route tuples into claim/public_inputs).
#
#        In other words, the full_stack profile evaluates what the family
#        would look like if it were upgraded to satisfy the unified
#        authorization semantics, using StateManager and
#        enriched evidence as idealized interfaces for the missing data.
#        This is useful for capability analysis and “what-if” hardening
#        experiments, not as a literal description of every deployed
#        bridge today.
# ================================================================


PROFILE_PIPELINES: Dict[str, List[PredicateName]] = {
    # Evidence-only enhanced profile
    # Full conceptual stack (ten predicates)
    "full_stack": list(CANONICAL_ORDER),
}


# ================================================================
# 5) Public API
# ================================================================

def get_pipeline_for_family(
    family: VerificationFamily,
    profile: str = "full_stack",
) -> List[Predicate]:
    """
    Construct a predicate pipeline for a given mechanism family and profile.

    Parameters
    ----------
    family : VerificationFamily
        The mechanism family whose behavior we are instantiating
        (MPC_TSS, OPTIMISTIC, ZK_LIGHT_CLIENT, NATIVE_LIGHT_CLIENT,
         HTLC, APPLICATION_WORKFLOW, ...).

    profile : str
        One of:
          - "native":
              Run only those predicates for which this family has some
              native capability (as recorded in FAMILY_NATIVE_CAPABILITIES),
              in the canonical order from CANONICAL_ORDER.

          - "full_stack" (default):
              Run the full ten-predicate stack defined in Table 4:
                  Authentic, HdrRef, DomainBind, ContextOK,
                  Contain, Final, Unique, Timely, Order, DomainOK.
              This corresponds to a hardened semantics where we *attempt*
              to check all properties, even if some families do not
              natively support them.

              NOTE: If some predicates are not yet implemented in code
              (i.e., they have no entry in REAL_PREDICATE_CLASSES),
              they are silently skipped when constructing the pipeline.
    Returns
    -------
    List[Predicate]
        A list of concrete Predicate instances in the order in which
        they should be evaluated.
    """
    # 1) Determine which predicate names should conceptually be in the pipeline
    if profile == "native":
        native = FAMILY_NATIVE_CAPABILITIES.get(family, [])
        # Preserve canonical ordering but only keep those the family
        # claims a native capability for.
        names = [n for n in CANONICAL_ORDER if n in native]
    else:
        if profile not in PROFILE_PIPELINES:
            raise ValueError(f"Unknown profile: {profile}")
        names = PROFILE_PIPELINES[profile]

    # 2) Filter out predicates that have no registered implementation yet.
    #    This allows us to express the full stack in terms of PredicateName
    #    even while some predicates are still “to be implemented”.
    concrete_names = [n for n in names if n in REAL_PREDICATE_CLASSES]

    # 3) Instantiate
    return [_make_pred(n) for n in concrete_names]
