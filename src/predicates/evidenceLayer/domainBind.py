from typing import List, Any, Dict, Tuple

from core.enums import PredicateName
from core.evidence import NativeLightClientEvidence, ZKLightClientEvidence, OptimisticEvidence, MPCEvidence
from predicates.base import PredicateResult, PredicateContext, PredicateLayer, Predicate


class DomainBindPredicate(Predicate):
    """
    DomainBind(m, e):

    Unified intuition:
      - The evidence e must be bound to the *same logical route* as the
        message m.
      - Our rules:
          * src / dst are mandatory and must match;
          * channel / bridge_id / asset_id / app_id / lane ... are optional;
            - if both sides provide a value and they differ → DomainBind = False
            - if one side is missing → DomainBind = True, but we record this
              as "unbound / partially bound" in metadata.

    We treat "route" as:
      - mandatory fields:   src, dst
      - optional fields:    channel, bridge_id, asset_id, app_id, lane, version, tenant
    """

    name = PredicateName.DOMAIN_BIND
    layer = PredicateLayer.EVIDENCE
    description = "Check that evidence is bound to the same logical route/domain as m."

    # Which extra route fields we try to align if present
    OPTIONAL_FIELDS: Tuple[str, ...] = (
        "channel",
        "bridge_id",
        "asset_id",
        "app_id",
        "lane",
        "version",
        "tenant",
    )

    def _route_from_message(self, ctx: PredicateContext) -> Dict[str, Any]:
        """
        Extract a 'route view' from the message m.

        Mandatory:
          - src, dst    (top-level on Message)

        Optional:
          - channel, bridge_id, asset_id, app_id, lane, version, tenant
            -> we attempt to read from m.meta.<field> if present.
        """
        m = ctx.m
        meta = getattr(m, "meta", None)

        route: Dict[str, Any] = {
            "src": m.src,
            "dst": m.dst,
        }

        if meta is not None:
            for field in self.OPTIONAL_FIELDS:
                # getattr(meta, field, None) will just give None if not set
                route[field] = getattr(meta, field, None)
        else:
            for field in self.OPTIONAL_FIELDS:
                route[field] = None

        return route

    def _route_from_evidence(self, ctx: PredicateContext) -> Dict[str, Any]:
        """
        Extract a 'route view' from the evidence e.

        For now we treat families as follows:
          - MPC_TSS: route comes from attestation.payload (if provided)
          - OPTIMISTIC: route comes from claim.route (src, dst, channel)
                         plus optional tags in claim.data
          - ZK_LIGHT_CLIENT: we *may* try to read src/dst/channel.. from public_inputs
                             using conventional keys, but do not hard-rely on them
          - NATIVE_LIGHT_CLIENT: typically the route is not encoded in e itself;
                                 we fall back to None for optional fields
        """
        e = ctx.e
        family = ctx.family

        route: Dict[str, Any] = {
            "src": None,
            "dst": None,
        }
        for field in self.OPTIONAL_FIELDS:
            route[field] = None

        # ---- 1) MPC_TSS: use attestation.payload ----
        if isinstance(e, MPCEvidence):
            payload = e.attestation.payload or {}

            # We assume the implementation *does* encode src/dst into the payload,
            # otherwise DomainBind cannot be meaningfully enforced.
            route["src"] = payload.get("src")
            route["dst"] = payload.get("dst")

            # Optional route fields (if the bridge chooses to encode them)
            for field in self.OPTIONAL_FIELDS:
                if field in payload:
                    route[field] = payload[field]

            return route

        # ---- 2) OPTIMISTIC: use claim.route + claim.data ----
        if isinstance(e, OptimisticEvidence):
            claim = e.claim
            if claim.route is not None:
                src, dst, chan = claim.route
                route["src"] = src
                route["dst"] = dst
                route["channel"] = chan

            data = claim.data or {}
            for field in self.OPTIONAL_FIELDS:
                # do NOT overwrite channel from claim.route with data["channel"]
                if field == "channel":
                    continue
                if field in data:
                    route[field] = data[field]

            return route

        # ---- 3) ZK_LIGHT_CLIENT: best-effort from public_inputs ----
        if isinstance(e, ZKLightClientEvidence):
            pi = e.public_inputs or {}

            # We try a few common key names for src/dst/channel,
            # but do not *require* them.
            route["src"] = (
                pi.get("src")
                or pi.get("src_chain")
                or pi.get("source_chain")
            )
            route["dst"] = (
                pi.get("dst")
                or pi.get("dst_chain")
                or pi.get("destination_chain")
            )
            route["channel"] = (
                pi.get("channel")
                or pi.get("channel_id")
            )

            # Extra tags could be present under standard names
            for field in self.OPTIONAL_FIELDS:
                if field in ("channel",):
                    continue  # already handled
                if field in pi:
                    route[field] = pi[field]

            return route

        # ---- 4) NATIVE_LIGHT_CLIENT: usually route is known out-of-band ----
        if isinstance(e, NativeLightClientEvidence):
            # Most native LC evidence only tells us "this header hs is valid";
            # the route policy is configured on D. We therefore keep src/dst
            # as None here and rely on DomainOK or configuration, not e.
            return route

        # ---- 5) Other families / runtime-only evidence: no route in e ----
        return route

    def evaluate(self, ctx: PredicateContext) -> PredicateResult:
        m_route = self._route_from_message(ctx)
        e_route = self._route_from_evidence(ctx)

        missing_on_e: List[str] = []
        mismatched: List[str] = []
        matched_optional: List[str] = []
        unbound_optional: List[str] = []

        # ---------- 1) mandatory src/dst ----------

        # src must exist on evidence and equal m.src
        if e_route["src"] is None or e_route["dst"] is None:
            # According to your rule: src/dst MUST be bound by the mechanism.
            return PredicateResult(
                name=self.name,
                ok=False,
                reason=(
                    "DomainBind: evidence does not bind src/dst explicitly; "
                    "src/dst are mandatory for domain binding."
                ),
                metadata={
                    "m_route": m_route,
                    "e_route": e_route,
                    "missing_on_e": [
                        f for f in ("src", "dst") if e_route[f] is None
                    ],
                },
            )

        if e_route["src"] != m_route["src"]:
            mismatched.append("src")

        if e_route["dst"] != m_route["dst"]:
            mismatched.append("dst")

        # If either src or dst mismatches, we fail immediately
        if mismatched:
            return PredicateResult(
                name=self.name,
                ok=False,
                reason=(
                    "DomainBind: src/dst mismatch between message and evidence "
                    f"({', '.join(mismatched)} differ)."
                ),
                metadata={
                    "m_route": m_route,
                    "e_route": e_route,
                    "mismatched": mismatched,
                },
            )

        # ---------- 2) optional fields: channel, bridge_id, asset_id, app_id, lane, ... ----------

        for field in self.OPTIONAL_FIELDS:
            mv = m_route.get(field)
            ev = e_route.get(field)

            # If both sides provide a value, it must match
            if mv is not None and ev is not None:
                if mv != ev:
                    mismatched.append(field)
                else:
                    matched_optional.append(field)
            else:
                # At least one side is missing → still ok, but record as "unbound"
                if mv is None and ev is None:
                    # completely absent on both sides: we just ignore
                    continue
                unbound_optional.append(field)
                if ev is None:
                    missing_on_e.append(field)

        if mismatched:
            # Optional fields mismatch → DomainBind = False
            return PredicateResult(
                name=self.name,
                ok=False,
                reason=(
                    "DomainBind: optional route fields mismatch "
                    f"({', '.join(mismatched)} differ)."
                ),
                metadata={
                    "m_route": m_route,
                    "e_route": e_route,
                    "mismatched": mismatched,
                    "matched_optional": matched_optional,
                    "unbound_optional": unbound_optional,
                    "missing_on_e": missing_on_e,
                    "note": (
                        "According to the model, optional fields are only required "
                        "to match if both sides provide them; mismatches cause failure."
                    ),
                },
            )

        # No mismatches: DomainBind passes.
        # But if we had unbound_optional / missing_on_e, we report that as
        # "partial domain binding" in metadata.
        return PredicateResult(
            name=self.name,
            ok=True,
            reason=None,
            metadata={
                "m_route": m_route,
                "e_route": e_route,
                "matched_optional": matched_optional,
                "unbound_optional": unbound_optional,
                "missing_on_e": missing_on_e,
                "note": (
                    "DomainBind: src/dst are strictly bound. "
                    "Other route fields (channel/bridge_id/asset_id/app_id/...) "
                    "are treated as soft: only mismatches fail; "
                    "missing fields are reported here but do not cause failure."
                ),
            },
        )
