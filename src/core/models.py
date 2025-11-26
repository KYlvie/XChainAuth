from __future__ import annotations
from typing import Any, Dict, Optional, Tuple
from pydantic import BaseModel, Field

JsonDict = Dict[str, Any]

# In unified predicates, a routing domain is represented as:
#     RouteTuple = (src_domain, dst_domain, optional)
RouteTuple = Tuple[str, str, Optional[str]]


# ======================================================================
# 1. MessageMeta — machine-checkable routing/control information
# ======================================================================

class MessageMeta(BaseModel):
    """
    Machine-checkable metadata associated with a cross-chain message.

    This corresponds to the “meta” component of m = (src, dst, payload, meta)
    in the unified semantics (§4.1).

    These fields are consumed by runtime predicates such as:
        • Unique(m, σ_runtime)
        • Order(m, σ_runtime)
        • Timely(m, e, σ_runtime)
        • DomainOK(m, σ_runtime)

    Key semantics:
        - seq:        per-channel sequence number
        - ttl:        time-to-live or freshness budget
        - timestamp:  logical or chain timestamp
        - channel:    logical channel/port identifier
        - extra:      any additional mechanism-specific metadata
    """

    seq: int = Field(
        ...,
        description="Per-channel sequence number used for ordering and replay protection.",
    )

    ttl: Optional[int] = Field(
        default=None,
        description="Time-to-live / freshness window used by Timely predicate.",
    )

    timestamp: Optional[int] = Field(
        default=None,
        description="Logical or chain timestamp associated with the message.",
    )

    channel: Optional[str] = Field(
        default=None,
        description="Logical channel or port used for routing and ordering.",
    )

    extra: JsonDict = Field(
        default_factory=dict,
        description="Additional machine-checkable metadata (mechanism- or application-specific).",
    )

    class Config:
        extra = "allow"


# ======================================================================
# 2. Message — cross-chain application message m = (src, dst, payload, meta)
# ======================================================================

class Message(BaseModel):
    """
    Cross-chain application message, as formalized in the unified semantics.

        m = (src, dst, payload, meta)

    • src, dst: Domain identifiers (chains, rollups, subnets, application scopes).
    • payload: Application-level content (opaque to the authorizer).
    • meta:    Routing/control metadata interpreted by runtime predicates.

    Source-chain provenance (src_tx_hash, src_height, src_index) is optional but
    useful for:
        - reconstructing message identity (MessageKey)
        - Contain predicates that reference source-chain structure
    """

    src: str = Field(
        ...,
        description="Source domain / chain identifier where the message originates.",
    )

    dst: str = Field(
        ...,
        description="Destination domain / chain identifier where authorization occurs.",
    )

    payload: JsonDict = Field(
        default_factory=dict,
        description="Opaque application payload. Not interpreted by the authorizer.",
    )

    meta: MessageMeta = Field(
        ...,
        description="Machine-checkable routing metadata (seq, TTL, channel, ...).",
    )

    src_tx_hash: Optional[str] = Field(
        default=None,
        description="Transaction hash on the source chain that emitted this message.",
    )

    src_height: Optional[int] = Field(
        default=None,
        description="Source-chain block height where the message was emitted.",
    )

    src_index: Optional[int] = Field(
        default=None,
        description="Event/log index within the source block or transaction.",
    )

    metadata: JsonDict = Field(
        default_factory=dict,
        description="Implementation-specific metadata not part of formal semantics.",
    )

    class Config:
        extra = "allow"

    def route_tuple(self) -> RouteTuple:
        """
        Extract the routing triple (src, dst, channel), used directly in:
            - DomainBind(m, e)
            - DomainOK(m, σ)
            - Order(m, σ)
        """
        return (self.src, self.dst, self.meta.channel)


# ======================================================================
# 3. Header — hs = HdrRef(e)
# ======================================================================

class Header(BaseModel):
    """
    Abstract source-chain header model used by unified predicates.

    A header represents the source state referenced by evidence e through:

        hs := HdrRef(e)

    Only fields relevant to cross-chain authorization are modeled here:
        • chain_id, height — identifies the block/state
        • state_root       — root of source-chain state commitment
        • tx_root          — Merkle root of transactions (optional)
        • receipts_root    — Merkle root of receipts (optional)
        • hash             — block hash / commitment
        • timestamp        — chain timestamp (for Timely and Final)
        • extra            — chain-specific metadata

    Different families may populate different subsets of these fields
    (e.g., optimistic protocols may omit tx_root; ZK circuits encode hashes
    as public inputs).
    """

    chain_id: str = Field(
        ...,
        description="Identifier of the chain this header belongs to.",
    )

    height: int = Field(
        ...,
        description="Block height of this header.",
    )

    parent_hash: Optional[str] = Field(
        default=None,
        description="Hash of the parent block (if provided).",
    )

    state_root: Optional[str] = None
    tx_root: Optional[str] = None
    receipts_root: Optional[str] = None

    hash: Optional[str] = Field(
        default=None,
        description="Hash/commitment of the header.",
    )

    timestamp: Optional[int] = Field(
        default=None,
        description="Wall-clock timestamp (UNIX seconds) on the source chain.",
    )

    extra: JsonDict = Field(
        default_factory=dict,
        description="Any additional chain-specific header data.",
    )

    class Config:
        extra = "allow"


# ======================================================================
# 4. MessageKey — canonical identity for Unique/replay predicates
# ======================================================================

class MessageKey(BaseModel):
    """
    Canonical identifier for a message instance used by Unique(m, σ_runtime)
    and replay-protection logic.

    Typical construction:
        key = (src, dst, channel, seq, src_tx_hash, src_index)

    This canonical identity allows the destination-side authorizer to
    determine whether a message has already been accepted.
    """

    src: str
    dst: str
    channel: Optional[str]
    seq: int

    src_tx_hash: Optional[str] = None
    src_index: Optional[int] = None

    def to_tuple(self) -> tuple:
        """
        Convert the key to a hashable tuple representation.
        """
        return (
            self.src,
            self.dst,
            self.channel,
            self.seq,
            self.src_tx_hash,
            self.src_index,
        )

    @classmethod
    def from_message(cls, m: Message) -> "MessageKey":
        """
        Construct a MessageKey directly from a Message instance.
        """
        return cls(
            src=m.src,
            dst=m.dst,
            channel=m.meta.channel,
            seq=m.meta.seq,
            src_tx_hash=m.src_tx_hash,
            src_index=m.src_index,
        )
