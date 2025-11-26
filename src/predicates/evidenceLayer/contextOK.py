# NOTE:
# In many real-world deployments, per-message context fields such as
# nonce/seq/channel/timestamp are either entirely absent or enforced only at
# the application layer. Even among systems that *do* carry such information,
# the naming conventions, the exact field set, and the location where these
# fields appear vary significantly between mechanism families.
#
# In our experimental framework, we therefore expose a *hardened* and
# family-agnostic version of these context fields using a unified vocabulary.
# This abstraction provides a common semantic surface for the ContextOK(e)
# predicate defined in §4.2, even though real protocols may call these fields
# differently or embed them in different structures.
#
# For families that natively support this predicate (e.g., protocols whose
# packet format already contains sequence numbers, channel identifiers, and
# timeouts), we adopt the convention that their native fields align with our
# declared vocabulary and appear in the same logical place. This allows the
# predicate to treat all families uniformly without overfitting to the quirks
# of any specific implementation.
from typing import Mapping, Optional, Any

from core.enums import VerificationFamily, PredicateName
from core.evidence import NativeLightClientEvidence, ZKLightClientEvidence, OptimisticEvidence, MPCEvidence
from predicates.base import PredicateResult, PredicateContext, PredicateLayer, Predicate


class ContextOKPredicate(Predicate):
    """
    ContextOK(e):

    High-level intent.
    ------------------
    This predicate checks *context soundness* of the runtimeLayer object e.
    It enforces that runtimeLayer is bound to the correct operational context
    so that it cannot be replayed across epochs, schemas, or channels.

    In the unified semantics (§4.2), ContextOK(e) corresponds to:
        KeyEpochOK(e) ∧ SchemaOK(e) ∧ AntiReplayOK(e)

    Concretely we realize a best-effort version per family:

      - MPC_TSS:
            use ev.attestation.payload as the signed context map.

      - OPTIMISTIC:
            try to extract a context map from:
              1) ev.meta["context"]
              2) ev.claim.data["context"]
              3) ev.meta      (if it already directly contains the fields)
              4) ev.claim.data

      - ZK_LIGHT_CLIENT:
            try to extract a context map from:
              1) ev.meta["context"]
              2) ev.public_inputs["context"]
              3) ev.meta
              4) ev.public_inputs

      - NATIVE_LIGHT_CLIENT:
            optionally use ctx.state.get_message_context(m) if available;
            otherwise treat ContextOK as a no-op with an explicit note.

      - Other families:
            ContextOK is treated as a no-op success, since they do not have
            a stable runtimeLayer-level context in our current model.

    Required fields (if context is present):
        - nonce         (existence only, for AntiReplayOK later)
        - seq           (int, equals m.meta.seq)
        - channel       (str, equals m.meta.channel)
        - timestamp     (int, equals m.meta.timestamp)

    The nonce/sequence/channel/timestamp fields in our ContextOK predicate are
    not meant to literally reflect every deployed bridge today.
    Instead, they capture a minimal context binding that a robust cross-chain
    mechanism ought to implement to avoid replay and misrouting.
    Many existing protocols partially satisfy these conditions (e.g., IBC packets,
    some rollup bridges), but others do not; our framework makes these gaps explicit
    rather than assuming all families already implement the full set of predicates natively.
    """

    name = PredicateName.CONTEXT_OK
    layer = PredicateLayer.EVIDENCE

    REQUIRED_FIELDS = {"nonce", "seq", "channel", "timestamp"}

    # ---------- generic helper to compare context vs m.meta ----------

    def _check_context_fields(
        self,
        ctx: PredicateContext,
        meta: Mapping[str, Any],
        family: VerificationFamily,
        source_label: str,
    ) -> PredicateResult:
        # 1) presence
        missing = [f for f in self.REQUIRED_FIELDS if f not in meta]
        if missing:
            return PredicateResult(
                name=self.name,
                ok=False,
                reason=(
                    f"ContextOK({family.value}): {source_label} missing required "
                    "fields: " + ", ".join(sorted(missing))
                ),
                metadata={
                    "family": family.value,
                    "source": source_label,
                    "present": list(meta.keys()),
                },
            )

        # 2) types
        try:
            seq_ev = int(meta["seq"])
            ts_ev = int(meta["timestamp"])
            chan_ev = str(meta["channel"])
        except (TypeError, ValueError):
            return PredicateResult(
                name=self.name,
                ok=False,
                reason=(
                    f"ContextOK({family.value}): {source_label} types are invalid "
                    "(expected int seq/timestamp and str channel)."
                ),
                metadata={
                    "family": family.value,
                    "source": source_label,
                    "payload": dict(meta),
                },
            )

        # 3) compare with m.meta
        if seq_ev != ctx.m.meta.seq:
            return PredicateResult(
                name=self.name,
                ok=False,
                reason=(
                    "ContextOK: payload.seq="
                    f"{seq_ev} != m.meta.seq={ctx.m.meta.seq}."
                ),
                metadata={"family": family.value, "source": source_label},
            )

        if chan_ev != ctx.m.meta.channel:
            return PredicateResult(
                name=self.name,
                ok=False,
                reason=(
                    "ContextOK: payload.channel="
                    f"{chan_ev} != m.meta.channel={ctx.m.meta.channel}."
                ),
                metadata={"family": family.value, "source": source_label},
            )

        if ts_ev != ctx.m.meta.timestamp:
            return PredicateResult(
                name=self.name,
                ok=False,
                reason=(
                    "ContextOK: payload.timestamp="
                    f"{ts_ev} != m.meta.timestamp={ctx.m.meta.timestamp}."
                ),
                metadata={"family": family.value, "source": source_label},
            )

        # nonce 目前只检查“存在”，真正的 AntiReplay 在 Unique/mailbox 层做
        return PredicateResult(
            name=self.name,
            ok=True,
            metadata={
                "family": family.value,
                "source": source_label,
                "present": list(meta.keys()),
                "note": f"{family.value}: context payload is consistent with message meta.",
            },
        )

    # ---------- small helpers to find a Mapping context ----------

    @staticmethod
    def _get_mapping(obj: Any) -> Optional[Mapping[str, Any]]:
        return obj if isinstance(obj, Mapping) else None

    def _find_opt_context(self, ev: OptimisticEvidence) -> Optional[Mapping[str, Any]]:
        # priority：meta["context"] → claim.data["context"] → meta → claim.data
        meta = ev.meta
        if isinstance(meta, Mapping):
            ctx_sub = meta.get("context")
            if isinstance(ctx_sub, Mapping):
                return ctx_sub

        if isinstance(ev.claim.data, Mapping):
            ctx_sub = ev.claim.data.get("context")
            if isinstance(ctx_sub, Mapping):
                return ctx_sub

        # if meta already contains required fields
        if isinstance(meta, Mapping) and self.REQUIRED_FIELDS.issubset(meta.keys()):
            return meta

        if isinstance(ev.claim.data, Mapping) and self.REQUIRED_FIELDS.issubset(
            ev.claim.data.keys()
        ):
            return ev.claim.data

        return None

    def _find_zk_context(self, ev: ZKLightClientEvidence) -> Optional[Mapping[str, Any]]:
        # priority：meta["context"] → public_inputs["context"] → meta → public_inputs
        meta = ev.meta
        if isinstance(meta, Mapping):
            ctx_sub = meta.get("context")
            if isinstance(ctx_sub, Mapping):
                return ctx_sub

        if isinstance(ev.public_inputs, Mapping):
            ctx_sub = ev.public_inputs.get("context")
            if isinstance(ctx_sub, Mapping):
                return ctx_sub

        if isinstance(meta, Mapping) and self.REQUIRED_FIELDS.issubset(meta.keys()):
            return meta

        if isinstance(ev.public_inputs, Mapping) and self.REQUIRED_FIELDS.issubset(
            ev.public_inputs.keys()
        ):
            return ev.public_inputs

        return None

    # ------------------------------ main evaluate ------------------------------

    def evaluate(self, ctx: PredicateContext) -> PredicateResult:
        family = ctx.family
        ev = ctx.e

        # 1) MPC/TSS: attestation.payload is our context map
        if family == VerificationFamily.MPC_TSS and isinstance(ev, MPCEvidence):
            meta = ev.attestation.payload or {}
            return self._check_context_fields(
                ctx=ctx,
                meta=meta,
                family=family,
                source_label="MPC attestation payload",
            )

        # 2) OPTIMISTIC: find context in meta / claim.data
        if family == VerificationFamily.OPTIMISTIC and isinstance(
            ev, OptimisticEvidence
        ):
            meta = self._find_opt_context(ev)
            if meta is None:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        "ContextOK(OPT): no suitable context map found. "
                        "Expected fields in runtimeLayer.meta['context'] or "
                        "claim.data['context'] (or directly in those maps)."
                    ),
                    metadata={"family": family.value},
                )

            return self._check_context_fields(
                ctx=ctx,
                meta=meta,
                family=family,
                source_label="Optimistic context",
            )

        # 3) ZK Light-Client: context from meta / public_inputs
        if family == VerificationFamily.ZK_LIGHT_CLIENT and isinstance(
            ev, ZKLightClientEvidence
        ):
            meta = self._find_zk_context(ev)
            if meta is None:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        "ContextOK(ZK): no suitable context map found. "
                        "Expected fields in runtimeLayer.meta['context'] or "
                        "public_inputs['context'] (or directly in those maps)."
                    ),
                    metadata={"family": family.value},
                )

            return self._check_context_fields(
                ctx=ctx,
                meta=meta,
                family=family,
                source_label="ZK public context",
            )

        # 4) Native Light-Client: optionally ask StateManager
        if family == VerificationFamily.NATIVE_LIGHT_CLIENT and isinstance(
            ev, NativeLightClientEvidence
        ):
            try:
                # interface：in ExperimentalStateManager(StateManager)
                meta = ctx.state.get_message_context(ctx.m)  # type: ignore[attr-defined]
            except AttributeError:
                # if not implemented no-op，with message
                return PredicateResult(
                    name=self.name,
                    ok=True,
                    metadata={
                        "family": family.value,
                        "note": (
                            "ContextOK(NLC): StateManager has no "
                            "get_message_context(m); treated as no-op. "
                            "You can add this API to enforce stronger "
                            "context checks from the source-chain mirror."
                        ),
                    },
                )

            if meta is None:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        "ContextOK(NLC): get_message_context(m) returned None; "
                        "cannot validate per-message context from chain view."
                    ),
                    metadata={"family": family.value},
                )

            if not isinstance(meta, Mapping):
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        "ContextOK(NLC): get_message_context(m) did not return "
                        "a mapping; expected a dict-like context object."
                    ),
                    metadata={
                        "family": family.value,
                        "context_type": type(meta).__name__,
                    },
                )

            return self._check_context_fields(
                ctx=ctx,
                meta=meta,
                family=family,
                source_label="Native LC chain-context (StateManager)",
            )

        # 5) Other families: currently no runtimeLayer-level context notion
        return PredicateResult(
            name=self.name,
            ok=True,
            metadata={
                "family": family.value,
                "note": (
                    "ContextOK not specifically implemented for this family; "
                    "treated as no-op context check."
                ),
            },
        )

