from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Optional, Set, Tuple

from core.enums import VerificationFamily
from core.models import Header, MessageKey, RouteTuple

import json

# ======================================================================
# 0. HeaderView — a lightweight mirror of source-chain headers
# ======================================================================

@dataclass
class HeaderView:
    """
    Lightweight representation of a source-chain header within the
    destination-chain environment.

    This class is purely a *state record* and carries no verification
    logic of its own. It allows predicates such as Final(h_s, σ) and
    Contain(m, e) to retrieve the subset of source-chain information
    that is relevant for unified authorization semantics.

    Fields:
        header: A full Header struct containing (chain_id, height,
                state_root, hash, and any chain-specific metadata).
        is_final: Boolean flag indicating whether this header has been
                  marked as final *according to the current σ view*.

    Important:
        • StateManager does *not* determine finality itself.
          - In experiments, SimulationChain or test code sets this flag.
          - In production systems, native light clients, ZK verifiers,
            BFT committees, or watcher modules would mark a header as
            final when their own protocol-specific checks succeed.

        • StateManager therefore acts only as a mirror of whatever
          upstream module claims a header is final. It preserves the
          information for predicates to consume.
    """
    header: Header
    is_final: bool = False


# ======================================================================
# 1. Abstract Interface: StateManager
#
#    σ = σ_chain (header mirror) + σ_runtime (message-ordering state)
# ======================================================================

class StateManager(ABC):
    """
    Abstract interface for the state σ used by runtime-layer predicates.

    In the unified predicate semantics (§4.2), σ is the conceptual
    destination-side state used to evaluate predicates such as:

        - Unique(m, σ)
        - Order(m, σ)
        - DomainOK(m, σ)
        - Final(h_s, σ)
        - Contain(m, h_s, σ)
        - Timely(m, e, σ)

    This interface provides exactly the minimal information needed for
    evaluating these predicates. It includes *two logically distinct
    components*:

        (1) σ_chain: A mirror of source-chain header views.
            Stored as (chain_id, height) → HeaderView.
            Used by Final and Contain predicates.

        (2) σ_runtime: Local runtime bookkeeping maintained by the
            Authorizer on the destination side, including:
                - processed message set (Unique)
                - per-route sequence expectations (Order)
                - routing policy tables (DomainOK)

    Crucially:
        • StateManager contains *no family-specific logic*.
          All mechanism-dependent interpretation is done exclusively
          in the predicate implementations under `predicates/`.

        • StateManager merely stores and exposes information; it does
          not decide correctness or validity of headers/messages.

        • This makes the design modular: consensus, MPC committees,
          ZK verifiers, optimistic mechanisms, and application workflows
          can all write state into the same σ interface, and predicates
          evaluate them uniformly.
    """

    # --------------------------------------------------------------
    # 1.1 Source-chain header mirror (σ_chain)
    # --------------------------------------------------------------

    @abstractmethod
    def record_header_view(self, header: Header, is_final: bool = False) -> None:
        """
        Insert or update a header view in σ_chain.

        Usage scenarios:
            • Experimental setting:
                SimulationChain generates headers and calls this method.
            • Real deployments:
                - Light clients write verified headers here.
                - ZK verifiers write headers after proof acceptance.
                - Watchers / committees record finalization events.

        No cryptographic checks occur here. StateManager merely stores
        whatever the upstream verification module claims.
        """
        raise NotImplementedError

    @abstractmethod
    def get_header_view(self, chain_id: str, height: int) -> Optional[Header]:
        """
        Look up a header previously recorded in σ_chain.
        Returns None if this header has never been observed.

        Predicates use this to:
            - Compare evidence-provided headers with mirrored headers.
            - Reconstruct the chain view relevant to HdrRef(e).
        """
        raise NotImplementedError

    @abstractmethod
    def is_final_header(self, header: Header) -> bool:
        """
        Return True iff this header has been marked as final in σ_chain.

        Important:
            • StateManager does not compute finality.
              It only returns whatever was previously recorded.

            • Predicates (Final(h_s)) rely on this method to reason about
              chain reorgs, equivocation, or unfinalized states.
        """
        raise NotImplementedError

    # --------------------------------------------------------------
    # 1.2 Message-uniqueness (σ_runtime — replay protection)
    # --------------------------------------------------------------

    @abstractmethod
    def has_seen_message(self, key: MessageKey) -> bool:
        """
        Return True iff this message key is already recorded as processed.

        Implements:
            Unique(m, σ_runtime)
        """
        raise NotImplementedError

    @abstractmethod
    def mark_message_seen(self, key: MessageKey) -> None:
        """
        Mark a message as processed.

        Implements:
            σ_runtime ← σ_runtime ∪ { key }
        """
        raise NotImplementedError

    # --------------------------------------------------------------
    # 1.3 Per-route ordering API (Order predicate)
    # --------------------------------------------------------------

    @abstractmethod
    def get_next_seq(self, route: RouteTuple) -> Optional[int]:
        """
        Return the expected next sequence number for a given route
        (src, dst, chan). Returns None if this is the first message
        ever encountered on this route.

        Order(m, σ) uses this to enforce per-channel ordering.
        """
        raise NotImplementedError

    @abstractmethod
    def advance_seq(self, route: RouteTuple, observed_seq: int) -> None:
        """
        Advance the expected sequence number after accepting a message
        with seq = observed_seq.

        Default policy:
            next_seq = max(existing_next_seq, observed_seq + 1)
        """
        raise NotImplementedError

    # --------------------------------------------------------------
    # 1.4 Routing-policy API (DomainOK predicate)
    # --------------------------------------------------------------

    @abstractmethod
    def is_route_allowed(self, route: RouteTuple) -> bool:
        """
        Return True iff (src, dst, attr.) is permitted by σ_runtime's
        routing policy configuration.

        Implements:
            DomainOK(m, σ_runtime)

        Default policy (if no table configured):
            allow all routes.
        """
        raise NotImplementedError

    # --------------------------------------------------------------
    # 1.5 Inflight API (Contain predicate — runtime variant)
    # --------------------------------------------------------------

    @abstractmethod
    def add_inflight(self, key: MessageKey, header: Header) -> None:
        """
        Mark a message as inflight at a given header.

        This API is useful for runtime-only containment (e.g., workflow messages).
        """
        raise NotImplementedError

    @abstractmethod
    def remove_inflight(self, key: MessageKey, header: Header) -> None:
        """
        Remove a message from the inflight set, typically after it is
        consumed, canceled, or invalidated.
        """
        raise NotImplementedError

    @abstractmethod
    def is_inflight(self, key: MessageKey, header: Header) -> bool:
        """
        Check whether a message is still considered live under this header.
        """
        raise NotImplementedError
# --- Fraud-proof related helpers (for optimistic family) -----------------
    @abstractmethod
    def record_fraud_proof(self, claim_id: str, t: Optional[int] = None) -> None:
        """
        Record that a fraud proof has been observed for the given claim_id.

        Parameters
        ----------
        claim_id : str
            Logical identifier of the optimistic claim (e.g. ev.claim.claim_id).
        t : Optional[int]
            Optional time / height at which the fraud proof was observed.
            Semantics depend on the experiment (timestamp vs. block height).
            Default implementation ignores this and does nothing.

        """
        # default: do nothing
        raise NotImplementedError

    @abstractmethod
    def has_fraud_proof(self, claim_id: str, up_to: Optional[int] = None) -> bool:
        """
        Check whether a fraud proof has been recorded for the given claim_id.

        Parameters
        ----------
        claim_id : str
            Logical identifier of the optimistic claim.
        up_to : Optional[int]
            Optional upper bound (timestamp / height) for when the fraud proof
            must have been observed. If None, any time is accepted.

        Returns
        -------
        bool
            True  if a fraud proof is known for this claim_id (and, if up_to is
                  provided, it was observed at or before 'up_to').
            False otherwise.

        """
        raise NotImplementedError

# ======================================================================
# 2. Concrete In-memory Implementation (generic, family-agnostic)
# ======================================================================

class InMemoryStateManager(StateManager):
    """
    Family-agnostic in-memory implementation of σ.

    Design goals:
        • Unified storage for all predicate families.
        • No embedded mechanism-specific logic.
        • Minimal, deterministic behavior suitable for experiments.

    Internal structure:
        _headers:      (chain_id, height) → HeaderView
        _seen:         set[str]                  (Unique)
        _inflight:     set[(canon_key, (cid,h))] (Contain-runtime)
        _next_seq:     dict[RouteTuple, int]     (Order)
        _allowed_routes: Optional[set[RouteTuple]]
    """

    def __init__(self) -> None:
        self._headers: Dict[Tuple[str, int], HeaderView] = {}
        self._seen: Set[str] = set()
        self._inflight: Set[Tuple[str, Tuple[str, int]]] = set()
        self._next_seq: Dict[RouteTuple, int] = {}
        self._allowed_routes: Optional[Set[RouteTuple]] = None

    # --------------------------------------------------------------
    # 2.1 Header mirror implementation
    # --------------------------------------------------------------

    def record_header_view(self, header: Header, is_final: bool = False) -> None:
        key = (header.chain_id, header.height)
        existing = self._headers.get(key)
        if existing is None:
            self._headers[key] = HeaderView(header=header, is_final=is_final)
        else:
            # Update header and/or finality marker
            existing.header = header
            existing.is_final = is_final or existing.is_final

    def get_header_view(self, chain_id: str, height: int) -> Optional[Header]:
        view = self._headers.get((chain_id, height))
        return view.header if view is not None else None

    def is_final_header(self, header: Header) -> bool:
        view = self._headers.get((header.chain_id, header.height))
        return bool(view and view.is_final)

    # --------------------------------------------------------------
    # 2.2 Unique / replay
    # --------------------------------------------------------------

    def has_seen_message(self, key: MessageKey) -> bool:
        return self._canon_key(key) in self._seen

    def mark_message_seen(self, key: MessageKey) -> None:
        self._seen.add(self._canon_key(key))

    # --------------------------------------------------------------
    # 2.3 Inflight
    # --------------------------------------------------------------

    def _inflight_key(self, key: MessageKey, header: Header) -> Tuple[str, Tuple[str, int]]:
        return self._canon_key(key), (header.chain_id, header.height)

    def add_inflight(self, key: MessageKey, header: Header) -> None:
        self._inflight.add(self._inflight_key(key, header))

    def remove_inflight(self, key: MessageKey, header: Header) -> None:
        self._inflight.discard(self._inflight_key(key, header))

    def is_inflight(self, key: MessageKey, header: Header) -> bool:
        return self._inflight_key(key, header) in self._inflight

    # --------------------------------------------------------------
    # 2.4 Order
    # --------------------------------------------------------------

    def get_next_seq(self, route: RouteTuple) -> Optional[int]:
        return self._next_seq.get(route)

    def advance_seq(self, route: RouteTuple, observed_seq: int) -> None:
        desired_next = observed_seq + 1
        current = self._next_seq.get(route)
        if current is None or desired_next > current:
            self._next_seq[route] = desired_next

    # --------------------------------------------------------------
    # 2.5 DomainOK policy
    # --------------------------------------------------------------

    def is_route_allowed(self, route: RouteTuple) -> bool:
        if self._allowed_routes is None:
            return True  # default: allow all
        return route in self._allowed_routes

    def set_allowed_routes(self, routes: Optional[Set[RouteTuple]]) -> None:
        self._allowed_routes = routes

    def list_allowed_routes(self):
        """
        Return the current routing policy as a set of RouteTuple entries.

        This extended API is mainly for experiments and debugging:
        in production one would typically store routing policy on-chain
        or in a configuration module.
        """
        return set(self._allowed_routes)

    def record_fraud_proof(self, claim_id: str, t: Optional[int] = None) -> None:
        """
        Record a fraud proof for claim_id, keeping the earliest observed time.
        """
        if t is None:
            # if you do not care about time in a given experiment, you can
            # simply set a constant or 0 here
            t = 0
        prev = self._fraud_proofs.get(claim_id)
        if prev is None or t < prev:
            self._fraud_proofs[claim_id] = t

    def has_fraud_proof(self, claim_id: str, up_to: Optional[int] = None) -> bool:
        """
        Return True if a fraud proof exists for claim_id and (optionally)
        was observed at or before 'up_to'.
        """
        t = self._fraud_proofs.get(claim_id)
        if t is None:
            return False
        if up_to is None:
            return True
        return t <= up_to

    # --------------------------------------------------------------
    # Helper: canonicalize MessageKey into a stable hashable string
    # --------------------------------------------------------------

    def _canon_key(self, key: MessageKey) -> str:
        """
        Convert a MessageKey object into a deterministic string.
        Supports:
            • Pydantic v2: model_dump()
            • Pydantic v1: dict()
            • json() if present
            • Fallback to repr()

        Ensures that _seen and _inflight remain hashable.
        """
        if hasattr(key, "model_dump"):
            data = key.model_dump(mode="json")
            return json.dumps(data, sort_keys=True, separators=(",", ":"))

        if hasattr(key, "dict"):
            data = key.dict()
            return json.dumps(data, sort_keys=True, separators=(",", ":"))

        if hasattr(key, "json"):
            try:
                return key.json()
            except TypeError:
                pass

        return repr(key)


# ======================================================================
# 3. Factory
# ======================================================================

def make_default_state_manager(family: VerificationFamily) -> StateManager:
    """
    Factory method: currently all families share the same generic
    InMemoryStateManager implementation.

    Future extensions:
        • Native light clients could have a specialized subclass.
        • ZK-based mechanisms might attach richer header metadata.
        • Workflows could maintain additional application-level state.
    """
    return InMemoryStateManager()
