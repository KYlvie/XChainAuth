
from __future__ import annotations
from core.enums import VerificationFamily, PredicateName
from predicates.base import Predicate, PredicateLayer, PredicateContext, PredicateResult
from core.evidence import (
    MPCEvidence,
    ZKLightClientEvidence,
    NativeLightClientEvidence,
    OptimisticEvidence,
)
from core.models import MessageKey


class UniquePredicate(Predicate):
    """
    Unique(m):

    Unified semantics:
      "Each cross-chain message m must be authorized at most once on the
       destination side. If the same logical message key is observed again,
       the predicate fails."

    Notes:
      - We treat "message identity" via a MessageKey constructed from
        (src, dst, channel, seq). This is a pragmatic choice that matches
        how mechanisms usually avoid cross-chain replays.
      - The StateManager is responsible for maintaining the replay set σ_D:
        it exposes has_seen_message(key) and mark_message_seen(key).
      - Whether Unique is enabled for a specific (family, profile) is decided
        by the registry, not here.
    """

    name = PredicateName.UNIQUE
    layer = PredicateLayer.RUNTIME
    description = "Destination-side replay protection over MessageKey."

    # ------------------------------------------------------------------
    # Helper: build a MessageKey from the current message
    # ------------------------------------------------------------------
    def _build_message_key(self, ctx: PredicateContext) -> MessageKey:
        """
        Construct the logical identity of the message.

        By default we use:
          - src: m.src
          - dst: m.dst
          - channel: m.meta.channel  (can be None)
          - seq: m.meta.seq

        If later MessageKey gains more fields (bridge_id, app_id, version,
        tenant...), we can extend this mapping accordingly.
        """
        m = ctx.m
        return MessageKey(
            src=m.src,
            dst=m.dst,
            channel=m.meta.channel,
            seq=m.meta.seq,
        )

    # ------------------------------------------------------------------
    # Main evaluation
    # ------------------------------------------------------------------
    def evaluate(self, ctx: PredicateContext) -> PredicateResult:
        state = ctx.state

        # Build the logical key for this message
        key = self._build_message_key(ctx)

        # Ask StateManager whether this key has been seen before
        if state.has_seen_message(key):
            # Replay detected: the same key was already authorized
            return PredicateResult(
                name=self.name,
                ok=False,
                reason=(
                    "Unique: message key has already been authorized on the "
                    "destination side."
                ),
                metadata={
                    "key": key.model_dump(mode="json"),
                },
            )

        # First time we see this key → mark as seen and pass
        state.mark_message_seen(key)
        return PredicateResult(
            name=self.name,
            ok=True,
            metadata={
                "key": key.model_dump(mode="json"),
                "note": "Message marked as seen for future replay checks.",
            },
        )
