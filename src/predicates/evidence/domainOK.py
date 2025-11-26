from __future__ import annotations
from typing import List, Optional, Tuple, Any
from predicates.base import Predicate, PredicateLayer, PredicateContext, PredicateResult
from core.enums import PredicateName
from core.models import RouteTuple


class DomainOKPredicate(Predicate):
    """
    DomainOK(m, σ):

    Runtime-level policy check on allowed routes.
    The policy is stored in the StateManager as a set of allowed RouteTuples.

    RouteTuple semantics:
        index 0 → src   (mandatory)
        index 1 → dst   (mandatory)
        index 2+ → optional route dimensions:
                     channel / bridge_id / asset_id / app_id / lane /
                     version / tenant / ...
    The order is fixed so that the same logical route always yields the
    same tuple shape when the same fields are present.

    Matching rules:
        - src/dst MUST match exactly.
        - For optional fields at index i:
            • if both policy[i] and msg[i] exist and differ → False
            • if only one exists → True, but recorded as partial match
            • if both missing → True

    The predicate is TRUE if at least one allowed_route matches.
    """

    name = PredicateName.DOMAIN_OK
    layer = PredicateLayer.RUNTIME

    def evaluate(self, ctx: PredicateContext) -> PredicateResult:
        state = ctx.state
        if state is None:
            return PredicateResult(
                name=self.name,
                ok=True,
                reason=None,
                metadata={
                    "placeholder": "no_state",
                    "note": "DomainOK: no StateManager provided; skipping route policy check.",
                },
            )

        # Build the message-side route tuple
        msg_route = self._route_from_message(ctx)

        allowed = ctx.state.list_allowed_routes()

        if allowed is None or len(allowed) == 0:
            # If policy is not configured → allow all
            return PredicateResult(
                name=self.name,
                ok=True,
                metadata={
                    "msg_route": msg_route,
                    "policy": None,
                    "note": "No route policy configured; treating DomainOK as True."
                }
            )

        matches: List[dict] = []
        for ar in allowed:
            ok, meta = self._match(msg_route, ar)
            if ok:
                matches.append(meta)

        if matches:
            return PredicateResult(
                name=self.name,
                ok=True,
                metadata={
                    "msg_route": msg_route,
                    "matched_policies": matches,
                }
            )

        # No allowed route matched → strict violation
        return PredicateResult(
            name=self.name,
            ok=False,
            reason=f"DomainOK: message route {msg_route} violates all policy routes.",
            metadata={
                "msg_route": msg_route,
                "allowed_routes": list(allowed),
            }
        )

    # ----------------------------------------------------------------------
    # Helper: extract message-side RouteTuple
    # ----------------------------------------------------------------------
    def _route_from_message(self, ctx: PredicateContext) -> RouteTuple:
        """
               Construct a route tuple from the message.

               Required:
                 - src, dst   (always first two elements)

               Optional (only appended if present and not None):
                 - channel
                 - bridge_id
                 - asset_id
                 - app_id
                 - lane
                 - version
                 - tenant

               The order is fixed so that the same logical route always yields the
               same tuple shape when the same fields are present.
               """
        meta = ctx.m.meta
        parts: List[str] = [ctx.m.src, ctx.m.dst]

        # optional channel
        chan = ctx.m.meta.channel
        if chan is not None:
            parts.append(str(chan))

        # optional extended route dimensions
        for field_name in [
            "bridge_id",
            "asset_id",
            "app_id",
            "lane",
            "version",
            "tenant",
        ]:
            value = getattr(meta, field_name, None)
            if value is not None:
                parts.append(str(value))

        # RouteTuple is typically defined as Tuple[str, ...]
        return tuple(parts)  # type: ignore[return-value]
    # ----------------------------------------------------------------------
    # Helper: match message route against one policy route
    # ----------------------------------------------------------------------
    def _match(self, msg: RouteTuple, policy: RouteTuple) -> Tuple[bool, dict]:
        meta = {
            "policy_route": policy,
            "partial_indices": []
        }

        # --- 1) src/dst must match ---
        if len(policy) < 2:
            return False, meta   # invalid policy

        if msg[0] != policy[0] or msg[1] != policy[1]:
            return False, meta

        # --- 2) compare remaining positions ---
        max_len = max(len(msg), len(policy))
        for i in range(2, max_len):
            mv = msg[i] if i < len(msg) else None
            pv = policy[i] if i < len(policy) else None

            if mv is not None and pv is not None:
                if mv != pv:
                    return False, meta  # mismatch
            else:
                # partial match: one side missing
                meta["partial_indices"].append(i)

        return True, meta
