from __future__ import annotations
from typing import Any, Dict, List, Optional, Literal
from pydantic import BaseModel, Field
from core.enums import VerificationFamily
from core.models import Header, RouteTuple  # RouteTuple = (src, dst, chan)

JsonDict = Dict[str, Any]

# ========== 1. Base: abstract Evidence ==========

class Evidence(BaseModel):
    """
    Abstract base class for cross-chain evidence e.

    In the unified semantics (§4.2), an evidence object e is the *mechanism-side
    justification* that allows the Authorizer on the destination chain to decide
    whether a message m is safe to accept.  It encapsulates whatever the specific
    mechanism family (MPC/TSS, Optimistic, ZK light client, native LC, etc.)
    chooses to expose as its security argument.

    Real-world interpretation
    -------------------------
    In deployed cross-chain systems, “evidence” is not a single standardized
    structure. Instead, it is produced organically by the mechanism family:

      • MPC/TSS (notary bridges):
          Evidence is generated off-chain by a committee that observes S,
          verifies the event, and produces a threshold signature over a tuple
          such as (m, header_hash). The destination chain contract receives
          only the attestation and minimal metadata—no Merkle proofs, no
          consensus views.

      • Optimistic bridges:
          Evidence is produced by a proposer/relayer submitting a claim
          (state_root, batch, etc.) plus a signature and an economic bond.
          Finality is enforced indirectly via challenge periods.

      • ZK Light Clients:
          Evidence is a ZK proof showing that a header, state root, or batch
          commitment is valid according to the source chain’s consensus rules.
          The on-chain verifier checks the proof, not the raw header structure.

      • Native Light Clients (GRANDPA, Tendermint, Ethereum LC):
          Evidence is the header h_s itself plus a finality proof (commit
          signatures, justification, sync committee proof), all consumed directly
          by the LC contract/module.

      • HTLC / Application Workflow:
          No cross-chain cryptographic evidence is exported. Trust is enforced
          through runtime behaviour (timeouts, hash-lock revelations, workflow
          order), so e is essentially an empty placeholder.

    Why unify these as `Evidence`?
    ------------------------------
    Although real families differ drastically, the Authorizer requires a common
    interface in order to run the unified predicates.  Therefore we impose only
    two minimal semantic requirements on e:

      (1) It belongs to exactly one verification family.
          This determines which cryptographic assumptions and runtime rules apply.

      (2) It may optionally expose a source-header reference via HdrRef(e).
          Families with header-level evidence (MPC/TSS, OPT, ZK LC, NLC) may
          support predicates like HdrRef, Final, Contain, etc.  Families lacking
          such evidence simply return None.

    All other fields (attestations, proofs, roots, context, metadata) are
    family-specific and intentionally left to subclasses. They are *not*
    standardized globally because real-world bridges do not expose a common ABI.

    This design allows our Authorizer to evaluate the 10 unified predicates
    over a heterogeneous ecosystem of mechanism families while keeping the
    abstraction faithful to deployed systems.
    """

    family: VerificationFamily = Field(
        ...,
        description="Verification family this evidence belongs to.",
    )

    # Family-specific / implementation-specific metadata.
    # This does not change the logical semantics, but is useful for
    # debugging, tracing, or experiment annotation.
    meta: JsonDict = Field(
        default_factory=dict,
        description="Implementation-specific metadata (not semantics-critical).",
    )

    class Config:
        # Allow additional fields in subclasses or when decoding from
        # JSON/dicts. Unknown keys will be stored alongside defined ones
        # instead of causing validation errors.
        extra = "allow"

    # --- Unified interface for HdrRef(e) ---
    def hdr_ref(self) -> Optional[Header]:
        """
        HdrRef(e): return the source header h_s referred to by this evidence,
        if any. Families that do not expose header-level evidence return None.

        This corresponds to the HdrRef(e) predicate input in the paper.
        """
        return None


# ========== MPC/TSS: CommitteeAttestation + MPCEvidence ==========

class CommitteeAttestation(BaseModel):
    """
    Attestation produced by an MPC/TSS committee.

    In real-world notary-style bridges, the pattern is roughly:
      - A set of off-chain committee nodes watch the source chain.
      - Each node performs local validation of the event / header.
      - They jointly produce a t-of-N threshold signature over a tuple
        such as (m, h_s) or (digest(m), h_s_hash).

    Here we only model the data; the actual signature checking is done
    by the Authentic(e) predicate or helper.crypto verifiers.
    """

    committee_id: str = Field(
        ...,
        description="Logical identifier of the committee.",
    )
    signature: str = Field(
        ...,
        description=(
            "Threshold / aggregated signature over a commitment tuple "
            "such as (m, h_s)."
        ),
    )
    signers: Optional[List[str]] = Field(
        default=None,
        description="Optional list of participating signers (IDs / public keys).",
    )
    payload: JsonDict = Field(
        default_factory=dict,
        description=(
            "Structured view of the signed payload (e.g. nonce/seq/channel/"
            "timestamp). In our model we *may* populate these fields to satisfy "
            "ContextOK(e), but real-world MPC deployments often omit some or "
            "all of them."
        ),
    )


class MPCEvidence(Evidence):
    """
    Evidence for MPC/TSS notary-style bridges (modeled after deployed systems).

    Typical structure:
      - A committee-produced threshold signature attestation; and
      - A reference to a source-chain header h_s (or an equivalent view).

    Important notes:
      - Many MPC/TSS bridges do *not* expose Merkle proofs or full header
        chains to the destination chain. The destination only learns that
        “the committee signed this tuple”.
      - Therefore, under the unified predicate semantics, Contain(m, h_s)
        and Final(h_s) are structurally unsupported for the MPC family:
        the Authorizer cannot independently re-derive state or finality from e.
        (See the capability analysis in Chapter 5.)
    """

    family: Literal[VerificationFamily.MPC_TSS] = VerificationFamily.MPC_TSS

    attestation: CommitteeAttestation = Field(
        ...,
        description="Committee-produced attestation over (m, h_s) or an "
                    "equivalent commitment tuple.",
    )

    header: Header = Field(
        ...,
        description="Source-chain header h_s referenced by this evidence.",
    )

    def hdr_ref(self) -> Optional[Header]:
        return self.header


# ========== OPTIMISTIC: evidence with a verifiable commitment ==========

class OptimisticClaim(BaseModel):
    """
    Logical claim in an optimistic mechanism.

    This represents a claim about a batch or state transition, such as:
      - state_root: claimed state root (e.g., rollup state root, bridge inbox root)
      - route: optional (src, dst, chan) routing context for the claim
      - data: additional batch/aggregation metadata
    """

    claim_id: Optional[str] = Field(
        default=None,
        description="Logical identifier of the claim (for dispute tracking).",
    )
    state_root: Optional[str] = Field(
        default=None,
        description="Claimed state root on the source chain.",
    )
    route: Optional[RouteTuple] = Field(
        default=None,
        description="Optional (src, dst, chan) route context the claim is about.",
    )
    data: JsonDict = Field(
        default_factory=dict,
        description="Mechanism-specific claim contents (batch info, etc.).",
    )


class OptimisticEvidence(Evidence):
    """
    Evidence for optimistic-verification mechanisms.

    At a high level we separate two components:

      1) Cryptographic commitment:
         - proposer_id: who submitted the claim (L1 contracts usually track
           a designated proposer or relayer role);
         - commitment_sig: signature over a canonical tuple such as
           (claim, header, dispute_window_end, ...).

      2) Economic / temporal guard:
         - dispute_window_end: end of the challenge window (block height or
           timestamp) during which fraud proofs can be submitted.

    Semantics:
      - Authentic(e) checks that “an authorized proposer’s signature is valid”.
      - Timely / Final and related runtime predicates ensure that the dispute
        window has expired, no valid fraud proof appeared, and thus the claim
        becomes accepted as correct.
    """

    family: Literal[VerificationFamily.OPTIMISTIC] = VerificationFamily.OPTIMISTIC

    # Logical statement: the state / batch being claimed
    claim: OptimisticClaim = Field(
        ...,
        description="Logical claim about a source state or batch.",
    )

    # Optional materialized header to which the claim is anchored.
    header: Optional[Header] = Field(
        default=None,
        description="Source-chain header referenced by this claim (if materialized).",
    )

    # --- Cryptographic commitment part ---

    proposer_id: Optional[str] = Field(
        default=None,
        description="Identifier of the proposer / relayer who submitted this claim.",
    )

    commitment_sig: Optional[str] = Field(
        default=None,
        description=(
            "Signature over a canonical tuple such as "
            "(claim_id, state_root, src_chain_id, dispute_window_end, ...). "
            "Authentic(OPTIMISTIC) will perform cryptographic checks on this field."
        ),
    )

    # --- Economic / temporal guard part ---

    dispute_window_end: Optional[int] = Field(
        default=None,
        description="End of the dispute window (height or timestamp).",
    )

    bond_tx_hash: Optional[str] = Field(
        default=None,
        description=(
            "Optional transaction hash of the bond / stake locked "
            "for this claim on the destination chain."
        ),
    )

    def hdr_ref(self) -> Optional[Header]:
        # The optimistic family can also provide a header reference if available.
        return self.header


# ========== ZK Light Client: ZK evidence with circuit identifiers ==========

class ZKLightClientEvidence(Evidence):
    """
    Evidence for ZK light-client style verification.

    Typical contents:
      - proof: the zero-knowledge proof object;
      - public_inputs: public inputs (header hash / slot / state_root / route, etc.);
      - circuit_id / vk_id: which ZK circuit and verification key are being used;
      - header: an optional materialized Header object for downstream predicates.

    The Authentic(e) predicate verifies the proof against the verification key,
    while other predicates (HdrRef, DomainBind, ContextOK, Contain, Final, ...)
    are driven by the structure of public_inputs and the optional header.
    """

    family: Literal[VerificationFamily.ZK_LIGHT_CLIENT] = VerificationFamily.ZK_LIGHT_CLIENT

    proof: JsonDict = Field(
        ...,
        description="Zero-knowledge proof object.",
    )
    public_inputs: JsonDict = Field(
        ...,
        description="Public inputs to the ZK verifier, including header identifiers.",
    )

    circuit_id: Optional[str] = Field(
        default=None,
        description="Identifier of the ZK circuit (program) used to generate this proof.",
    )

    vk_id: Optional[str] = Field(
        default=None,
        description="Identifier of the verification key used on-chain.",
    )

    header: Optional[Header] = Field(
        default=None,
        description="Materialized header h_s, if available.",
    )

    def hdr_ref(self) -> Optional[Header]:
        return self.header


# ========== Native Light Client: evidence with finality view ==========

class NativeLightClientEvidence(Evidence):
    """
    Evidence for native light-client based verification.

    In many systems, the “evidence” that the Authorizer sees is simply
    “a header that the light client has already validated”, optionally
    accompanied by explicit finality information:

      - header: a source-chain header h_s that has passed the LC's checks;
      - finality_proof: optional proof object (BFT commit, GRANDPA justification,
        Casper FFG proof, etc.);
      - lc_id: identifier of the light-client instance (contract address, module id).

    Authentic(e) and Final(h_s) can inspect this structure to enforce
    cryptographic consensus validity and finality semantics.
    """

    family: Literal[VerificationFamily.NATIVE_LIGHT_CLIENT] = VerificationFamily.NATIVE_LIGHT_CLIENT

    header: Header = Field(
        ...,
        description="Source-chain header h_s validated by a native light client.",
    )

    finality_proof: Optional[JsonDict] = Field(
        default=None,
        description=(
            "Optional proof object for finality (e.g., BFT commit, GRANDPA proof). "
            "Final(h_s) / Authentic(e) may perform structural checks here."
        ),
    )

    lc_id: Optional[str] = Field(
        default=None,
        description="Identifier of the light-client instance (e.g. contract address).",
    )

    def hdr_ref(self) -> Optional[Header]:
        return self.header


# Families that expose header+proof style cross-chain evidence and can
# support Authentic/HdrRef/DomainBind/ContextOK at the evidence layer.
FAMILIES_WITH_HEADER_EVIDENCE = {
    VerificationFamily.MPC_TSS,
    VerificationFamily.OPTIMISTIC,
    VerificationFamily.ZK_LIGHT_CLIENT,
    VerificationFamily.NATIVE_LIGHT_CLIENT,
}


# ========== 3. Pure runtime families: HTLC / Application workflow ==========

class HTLCEvidence(Evidence):
    """
    Evidence placeholder for HTLC-style mechanisms.

    In our unified semantics, HTLCs do not expose separate cross-chain
    header evidence. Safety is enforced entirely at the runtime layer
    by local contract logic (Timely, Unique, Order, DomainOK, ...).

    This class primarily exists as a shell to attach debugging metadata
    or to record lock parameters for experiments.
    """

    family: Literal[VerificationFamily.HTLC] = VerificationFamily.HTLC

    # These fields are not used by evidence-layer predicates. They are
    # only consumed by runtime-layer mappings or analysis.
    hash_lock: Optional[str] = None
    time_lock: Optional[int] = None
    extra: JsonDict = Field(default_factory=dict)


class WorkflowEvidence(Evidence):
    """
    Evidence placeholder for application-layer workflows.

    Similar to HTLC, we do not assume any dedicated header evidence at
    this layer. All safety properties are enforced by the application
    state machine via runtime-layer predicates (Order, Unique, DomainOK,
    Contain, etc.), if the workflow designer chooses to implement them.

    This class just provides a place to hang workflow identifiers and
    extra metadata for experiments.
    """

    family: Literal[VerificationFamily.APPLICATION_WORKFLOW] = VerificationFamily.APPLICATION_WORKFLOW

    workflow_id: Optional[str] = None
    step: Optional[str] = None
    extra: JsonDict = Field(default_factory=dict)


# Families that are “runtime-only” from the perspective of our unified
# semantics: they do not provide cross-chain header evidence, and thus
# cannot support evidence-layer predicates such as HdrRef or Contain.
FAMILIES_RUNTIME_ONLY = {
    VerificationFamily.HTLC,
    VerificationFamily.APPLICATION_WORKFLOW,
}
