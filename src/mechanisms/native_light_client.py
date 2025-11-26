# src/mechanisms/native_light_client.py
from __future__ import annotations

from typing import Any, Dict, Tuple
import json

from core.enums import VerificationFamily
from core.models import Message, MessageMeta, Header, MessageKey
from core.evidence import NativeLightClientEvidence
from core.state import StateManager
from mechanisms.base import Mechanism


class NativeLightClientMechanism(Mechanism):
    """
    Native light-client based mechanism.

    Intuition / model:
      - On the destination chain D, there exists a native light client
        (or module) that continuously tracks the source chain S and
        validates its headers (BFT signatures, PoW depth, etc.).
      - When an application wants to bridge a message m from S → D, it:
          * constructs m from an application event `app_event`;
          * uses the light client view to obtain a *validated* header h_s;
          * sends (m, e) to the Authorizer on D, where
                e = NativeLightClientEvidence(header = h_s).

    In our experimental framework:
      - The "light client view" is provided by StateManager + SimulationChain;
      - We *try* to obtain the header for (chain_id, height) from the
        StateManager (if it exposes such an API);
      - If no header is present, we fall back to constructing a header
        from app_event (height, state_root, hash) to keep the model runnable.

    """

    family = VerificationFamily.NATIVE_LIGHT_CLIENT


    # ---- Mechanism interface ----

    def build_message_and_evidence(
        self,
        *,
        src_chain_id: str,
        dst_chain_id: str,
        app_event: Dict[str, Any],
        state: StateManager,
        extra: Dict[str, Any] | None = None,
    ) -> Tuple[Message, NativeLightClientEvidence]:
        """
        Package an application event `app_event` into (m, e) for the
        Native Light Client family, and update evidenceLayer σ.

        Expected `app_event` fields (informal contract):
          - "payload": dict           → application-level payload
          - "seq": int                → message sequence number
          - "timestamp": int          → source-chain timestamp
          - "channel": str            → channel / route identifier
          - "height": int             → source header height
          - "state_root": str (opt)   → state root of the source chain at `height`
          - "header_hash": str (opt)  → block/header hash at `height`
          - (other fields are ignored here or only used for debugging)

        Header source (respecting reality as much as possible):
          - First we ask the StateManager for a header view for
                (src_chain_id, height) if it exposes a `get_header_view`
                or similar API (as in ExperimentalStateManager /
                SimulationChain);
          - If no such header is found, we fall back to constructing a
            header from the app_event's fields. This mirrors the idea
            that the light client *could* have validated such a header,
            but in our experiment we may not always pre-populate the
            chain.
        """
        seq = app_event.get("seq", 1)
        timestamp = app_event.get("timestamp", 0)
        channel = app_event.get("channel", "default")
        height = app_event.get("height", 0)

        payload = app_event.get("payload", {})
        state_root = app_event.get("state_root")
        header_hash = app_event.get("header_hash")

        route = (src_chain_id, dst_chain_id, channel)

        # --------------------------------------------------
        # 1. Construct message m
        # --------------------------------------------------
        meta = MessageMeta(
            seq=seq,
            ttl=None,           # TTL is enforced at predicate level (Timely)
            timestamp=timestamp,
            channel=channel,
        )
        m = Message(
            src=src_chain_id,
            dst=dst_chain_id,
            payload=payload,
            meta=meta,
        )

        # --------------------------------------------------
        # 2. Obtain / construct header h_s (light-client view)
        # --------------------------------------------------
        header: Header | None = None

        # (a) Try to use a light-client-like view from StateManager.
        #     ExperimentalStateManager implements `get_header_view` which
        #     delegates to SimulationChain.get_header().
        if hasattr(state, "get_header_view"):
            # type: ignore[call-arg]  # we know ExperimentalStateManager has this
            header = state.get_header_view(src_chain_id, height)  # type: ignore[attr-defined]

        # (b) If not available, construct a header directly from app_event.
        if header is None:
            header = Header(
                chain_id=src_chain_id,
                height=height,
                state_root=state_root,
                hash=header_hash,
            )

            # Optionally, if StateManager exposes an API to "register" this
            # header into the simulated chain, we can do it here so that
            # Final / Contain predicates can later use it.
            if hasattr(state, "register_header"):
                try:
                    # type: ignore[attr-defined]
                    state.register_header(header)   # purely experimental helper
                except Exception:
                    # Best-effort: if the specific StateManager doesn't support
                    # this, we simply skip registration.
                    pass

        # --------------------------------------------------
        # 3. Build NativeLightClientEvidence
        # --------------------------------------------------
        e = NativeLightClientEvidence(
            family=self.family,
            header=header,
            meta=extra or {},
        )


        # --------------------------------------------------
        # 5. Return (m, e)
        # --------------------------------------------------
        return m, e
