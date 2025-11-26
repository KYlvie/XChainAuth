# src/mechanisms/optimistic.py
from __future__ import annotations

from typing import Any, Dict, Tuple

from core.enums import VerificationFamily
from core.models import Message, MessageMeta, Header, MessageKey, RouteTuple
from core.evidence import OptimisticEvidence, OptimisticClaim
from core.state import StateManager
from mechanisms.base import Mechanism


class OptimisticMechanism(Mechanism):
    """
    Optimistic verification mechanism (rollups / optimistic bridges).

    Responsibilities:
      - Wrap an application-level event `app_event` into a cross-chain
        Message `m`;
      - Construct an OptimisticClaim `claim` that represents the asserted
        source-state / batch, plus an optional header view `h_s`;
      - Set a dispute window end (height or timestamp) for Timely(m, e):
          * either taken directly from app_event["dispute_window_end"], or
          * derived from timestamp + window_length;
      - Write runtime state into σ (StateManager):
          * replay / Unique state via mark_message_seen();
          * inflight(m, h_s) via add_inflight();
          * per-route ordering via advance_seq(route, seq).

    This models the *best-case*, honest optimistic mechanism:
      - Provers/aggregators publish claims about source state;
      - There is a well-defined dispute window during which fraud proofs
        can be submitted;
      - If the window elapses without a valid fraud proof, the claim is
        treated as "accepted" on the destination side.
    """

    family = VerificationFamily.OPTIMISTIC

    # ---------------------------------------------------------------------
    # Mechanism interface
    # ---------------------------------------------------------------------

    def build_message_and_evidence(
        self,
        *,
        src_chain_id: str,
        dst_chain_id: str,
        app_event: Dict[str, Any],
        state: StateManager,
        extra: Dict[str, Any] | None = None,
    ) -> Tuple[Message, OptimisticEvidence]:
        """
        Package an application event `app_event` into (m, e) for the
        Optimistic family, and update runtime σ.

        Expected `app_event` fields (informal contract):
          - "payload": dict           → application-level payload
          - "seq": int                → message sequence number
          - "timestamp": int          → source-chain timestamp
          - "channel": str            → channel / route identifier
          - "height": int (opt)       → source header height
          - "state_root": str (opt)   → state root committed by the header
          - "header_hash": str (opt)  → block / header hash on the source chain

          - "claim_id": str (opt)     → logical claim identifier
          - "claim_data": dict (opt)  → additional batch / rollup data to
                                       put into OptimisticClaim.data

          - "dispute_window_end": int (opt) → explicit end of dispute window
          - "window_length": int (opt)      → if set and dispute_window_end
                                             is absent, we approximate:
                                               dispute_window_end =
                                                   timestamp + window_length

        Notes:
          - We do *not* check fraud proofs here. Fraud proofs are tracked
            at runtime in the StateManager (e.g. via record_fraud_proof)
            and consumed by Timely(OPTIMISTIC).
          - We treat height/timestamp as a single scalar timeline for
            simplicity: Timely decides how to interpret them.
        """
        # --------------------------------------------------
        # 1. Basic message parameters
        # --------------------------------------------------
        seq = app_event.get("seq", 1)
        timestamp = app_event.get("timestamp", 0)
        channel = app_event.get("channel", "default")

        # Header-related params (optional)
        height = app_event.get("height")
        state_root = app_event.get("state_root")
        header_hash = app_event.get("header_hash")

        # Claim-related params
        claim_id = app_event.get("claim_id")
        claim_data = app_event.get("claim_data") or {}

        # Dispute window configuration
        dispute_window_end = app_event.get("dispute_window_end")
        window_length = app_event.get("window_length")

        route: RouteTuple = (src_chain_id, dst_chain_id, channel)

        # --------------------------------------------------
        # 2. Construct message m
        # --------------------------------------------------
        meta = MessageMeta(
            seq=seq,
            ttl=None,            # TTL is left to Timely to interpret if enabled
            timestamp=timestamp,
            channel=channel,
        )

        payload = app_event.get("payload", {})
        m = Message(
            src=src_chain_id,
            dst=dst_chain_id,
            payload=payload,
            meta=meta,
        )

        # --------------------------------------------------
        # 3. Construct header h_s (optional but highly recommended)
        # --------------------------------------------------
        header: Header | None = None
        if height is not None or state_root is not None or header_hash is not None:
            # If any of the header-related fields are present, we materialize a Header.
            header = Header(
                chain_id=src_chain_id,
                height=height if height is not None else 0,
                state_root=state_root,
                hash=header_hash,
            )

        # --------------------------------------------------
        # 4. Construct OptimisticClaim
        # --------------------------------------------------
        claim = OptimisticClaim(
            claim_id=claim_id,
            state_root=state_root,
            route=route,
            data=claim_data,
        )

        # --------------------------------------------------
        # 5. Compute / derive dispute_window_end if needed
        # --------------------------------------------------
        if dispute_window_end is None and window_length is not None:
            try:
                window_len_int = int(window_length)
                dispute_window_end = int(timestamp) + window_len_int
            except (TypeError, ValueError):
                # If window_length is malformed we simply leave
                # dispute_window_end=None and let Timely complain later.
                dispute_window_end = None

        # --------------------------------------------------
        # 6. Build OptimisticEvidence
        # --------------------------------------------------
        e = OptimisticEvidence(
            family=self.family,
            claim=claim,
            header=header,
            dispute_window_end=dispute_window_end,
            meta=extra or {},
        )
        return m, e
