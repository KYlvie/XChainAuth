# src/predicates/order.py
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple, List

from core.enums import PredicateName
from predicates.base import Predicate, PredicateLayer, PredicateContext, PredicateResult


class OrderPredicate(Predicate):
    """
    Order(m, e): per-route sequencing predicate (placeholder implementation).

    Intended semantics (for future implementation):
      - Fix a "route" for the message, e.g.
          route = (src_chain, dst_chain, channel, bridge_id, app_id, ...)
      - The StateManager maintains a evidenceLayer view σ_D that stores, for each route,
        the expected next sequence number (or a more complex ordering state).
      - Order(m, e) should enforce that:
          * m.meta.seq is consistent with this per-route ordering policy:
              - typically seq(m) == next_seq(route)  (strict FIFO, no gaps), or
              - some relaxed variant defined by the mechanism / application.
      - If the message arrives "out of order" (seq too small, too large,
        or violates the configured sequencing rules), Order(m, e) = False.

    CURRENT STATUS:
      - This is a placeholder implementation.
      - It always returns ok=True and does NOT inspect σ or seq.
      - Metadata explicitly records that the predicate is not yet implemented,
        but is part of the profile pipeline.
    """

    name = PredicateName.ORDER
    layer = PredicateLayer.RUNTIME
    description = (
        "Per-route sequencing predicate. Placeholder: always ok=True; "
        "no ordering logic implemented yet."
    )

    def _route_from_message(self, ctx: PredicateContext) -> Tuple[str, ...]:
        """
        Construct a logical 'route' tuple from the message.

        Minimal form:
          (src_chain, dst_chain)

        Extended form (for future use):
          (src_chain, dst_chain, channel, bridge_id, asset_id, app_id, lane, version, tenant, ...)

        For now we only build the minimal form + optional channel, because
        the ordering logic is not implemented yet. This helper is here so
        that future implementations can reuse the same route construction.
        """
        parts: List[str] = [ctx.m.src, ctx.m.dst]

        # Optional channel, if present in meta
        chan = getattr(ctx.m.meta, "channel", None)
        if chan is not None:
            parts.append(str(chan))

        # Future extensions could append more fields here, e.g.:
        # bridge_id = getattr(ctx.m.meta, "bridge_id", None)
        # if bridge_id is not None:
        #     parts.append(str(bridge_id))
        #
        # asset_id = getattr(ctx.m.meta, "asset_id", None)
        # if asset_id is not None:
        #     parts.append(str(asset_id))
        #
        # app_id = getattr(ctx.m.meta, "app_id", None)
        # if app_id is not None:
        #     parts.append(str(app_id))
        #
        # lane = getattr(ctx.m.meta, "lane", None)
        # if lane is not None:
        #     parts.append(str(lane))
        #
        # version = getattr(ctx.m.meta, "version", None)
        # if version is not None:
        #     parts.append(str(version))
        #
        # tenant = getattr(ctx.m.meta, "tenant", None)
        # if tenant is not None:
        #     parts.append(str(tenant))

        return tuple(parts)

    def evaluate(self, ctx: PredicateContext) -> PredicateResult:
        """
        Placeholder evaluation:
          - Compute a route tuple (for debugging / future use).
          - Always return ok=True.
          - Mark in metadata that ordering semantics are NOT enforced yet.
        """
        route = self._route_from_message(ctx)
        seq = getattr(ctx.m.meta, "seq", None)

        return PredicateResult(
            name=self.name,
            ok=True,  # Always true for now
            reason="Order predicate is a placeholder; no sequencing semantics implemented yet.",
            metadata={
                "family": ctx.family.value,
                "route": route,
                "seq": seq,
                "note": (
                    "Order(m, e) is currently a no-op (always True). "
                    "In a complete implementation, this would enforce per-route "
                    "sequence monotonicity / FIFO using StateManager state."
                ),
            },
        )
