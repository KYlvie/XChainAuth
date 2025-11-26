from typing import Optional, Dict, Any

from core.enums import PredicateName, VerificationFamily
from predicates.base import Predicate, PredicateLayer, PredicateContext, PredicateResult
from core.evidence import OptimisticEvidence, HTLCEvidence


class TimelyPredicate(Predicate):
    """
    Timely(m, e):

    Unified high-level meaning:
      - Enforce that a cross-chain message is neither accepted too early
        nor too late, according to the time semantics of the mechanism
        family and the experiment configuration.

    Family-specific semantics in this model:

      • OPTIMISTIC:
          - Uses three layers:
              (1) m.meta.ttl (optional upper bound; if present and expired → False);
              (2) ev.dispute_window_end (optimistic challenge window; while now
                  < dispute_window_end the claim is *pending*, not yet eligible
                  for acceptance);
              (3) optional freshness bound ctx.params['max_age'] based on
                  m.meta.timestamp.
          - If dispute_window_end is after TTL (when TTL is set), we treat it as
            a misconfiguration and return False.
          - A fraud proof for ev.claim.claim_id (if flagged in ctx.params) also
            makes Timely(m, e) = False.

      • HTLC:
          - Models hash-time-locked contracts with:
              - ev.time_lock (timelock / deadline on the HTLC itself), and
              - optional m.meta.ttl.
          - At least one of {time_lock, ttl} must be present; otherwise we treat
            the configuration as violating HTLC timelock semantics.
          - The effective deadline is min(time_lock, ttl) among the values that
            are set. If now > effective_deadline, the message is considered
            expired and Timely(m, e) = False.
          - Optional max_age (based on m.meta.timestamp) can be used as an
            additional freshness bound.

      • MPC_TSS / ZK_LIGHT_CLIENT / NATIVE_LIGHT_CLIENT:
          - Once Timely is enabled for these families, we require an explicit
            TTL in m.meta.ttl.
          - If TTL is missing → Timely(m, e) = False.
          - If now > ttl → Timely(m, e) = False.
          - Optional ctx.params['max_age'] can further restrict how old the
            message is allowed to be relative to m.meta.timestamp.

      • Any other family:
          - If Timely is present in the pipeline but no semantics are defined,
            we return False with an explicit explanation, instead of silently
            treating it as “passed”.
    """
    name = PredicateName.TIMELY
    layer = PredicateLayer.RUNTIME
    description = (
        "Timely(m, e): enforces TTL and, for specific families, additional "
        "time-related semantics (optimistic dispute window, HTLC timelock)."
    )

    def evaluate(self, ctx: PredicateContext) -> PredicateResult:
        family = ctx.family
        m = ctx.m
        now = ctx.now

        # ============================================================
        # Helper 1: parse TTL from message meta
        # ============================================================
        def _parse_ttl() -> Optional[int]:
            """
            Parse TTL from m.meta.ttl if present.

            Returns:
              - int(ttl) if set and valid
              - None     if no TTL is set
            Raises:
              - ValueError if the TTL value cannot be parsed as int
            """
            ttl_raw = m.meta.ttl
            if ttl_raw is None:
                return None
            try:
                return int(ttl_raw)
            except (TypeError, ValueError):
                raise ValueError(f"Invalid TTL value in m.meta.ttl={ttl_raw!r}")

        # ============================================================
        # Helper 2: optional max_age based on timestamp
        # ============================================================
        def _check_max_age(metadata: Dict[str, Any]) -> Optional[PredicateResult]:
            """
            If ctx.params['max_age'] is set, enforce a freshness bound:
                age = now - m.meta.timestamp <= max_age

            Returns:
              - PredicateResult if the check fails,
              - None if the check passes or max_age is not configured.
            """
            max_age = ctx.params.get("max_age")
            if max_age is None:
                return None

            try:
                max_age_int = int(max_age)
            except (TypeError, ValueError):
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=f"Timely: invalid max_age param={max_age!r}.",
                    metadata={"max_age": max_age},
                )

            if m.meta.timestamp is None:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        "Timely: max_age configured but m.meta.timestamp is missing."
                    ),
                    metadata={"max_age": max_age_int},
                )

            try:
                ts_int = int(m.meta.timestamp)
            except (TypeError, ValueError):
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        f"Timely: invalid m.meta.timestamp={m.meta.timestamp!r} "
                        "for max_age check."
                    ),
                    metadata={"max_age": max_age_int},
                )

            age = now - ts_int
            if age > max_age_int:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        "Timely: message too old relative to timestamp "
                        f"(age={age} > max_age={max_age_int})."
                    ),
                    metadata={
                        "now": now,
                        "timestamp": ts_int,
                        "age": age,
                        "max_age": max_age_int,
                    },
                )

            # passed max_age check → record it in metadata, but no failure
            metadata.update(
                {
                    "timestamp": ts_int,
                    "age": age,
                    "max_age": max_age_int,
                }
            )
            return None

        # ------------------------------------------------------------
        # Case 1: OPTIMISTIC – TTL + dispute window + fraud proofs
        # ------------------------------------------------------------
        if family == VerificationFamily.OPTIMISTIC:
            assert isinstance(ctx.e, OptimisticEvidence)
            ev = ctx.e

            # 1) parse TTL first (global upper bound)
            try:
                ttl_int = _parse_ttl()
            except ValueError as exc:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=f"Timely(OPTIMISTIC): {exc}",
                    metadata={"now": now},
                )

            # If TTL is present and already expired → Timely = False
            if ttl_int is not None and now > ttl_int:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        "Timely(OPTIMISTIC): message TTL expired "
                        f"(now={now} > ttl={ttl_int})."
                    ),
                    metadata={"now": now, "ttl": ttl_int},
                )

            # 2) dispute_window_end must be present
            if ev.dispute_window_end is None:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        "Timely(OPTIMISTIC): dispute_window_end is missing in runtimeLayer."
                    ),
                    metadata={"now": now, "ttl": ttl_int},
                )

            try:
                window_end = int(ev.dispute_window_end)
            except (TypeError, ValueError):
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        "Timely(OPTIMISTIC): invalid dispute_window_end "
                        f"value={ev.dispute_window_end!r}."
                    ),
                    metadata={"now": now, "ttl": ttl_int},
                )

            # 3) Dispute window must lie within TTL horizon if TTL is set
            if ttl_int is not None and window_end > ttl_int:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        "Timely(OPTIMISTIC): dispute window ends after TTL "
                        f"(dispute_window_end={window_end} > ttl={ttl_int}); "
                        "this configuration is inconsistent."
                    ),
                    metadata={
                        "now": now,
                        "ttl": ttl_int,
                        "dispute_window_end": window_end,
                        "window_outside_ttl": True,
                    },
                )

            # 4) While inside the dispute window, the claim is pending:
            #    - not yet eligible for acceptance on D
            #    - this is *not* a “fake” message; just pending
            if now < window_end:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        "Timely(OPTIMISTIC): claim is still within the dispute window; "
                        "it is pending and not yet eligible for acceptance at time 'now'."
                    ),
                    metadata={
                        "now": now,
                        "dispute_window_end": window_end,
                        "ttl": ttl_int,
                        "pending": True,
                    },
                )

            metadata: Dict[str, Any] = {
                "now": now,
                "dispute_window_end": window_end,
                "ttl": ttl_int,
            }

            # 4) Fraud proof status from StateManager (not from params)
            claim_id = ev.claim.claim_id
            if claim_id is not None:
                # We check whether a fraud proof has been observed at or before
                # the end of the dispute window. This approximates the usual
                # semantics: if a valid fraud proof exists in time, the claim
                # must not be accepted as Timely.
                if ctx.state.has_fraud_proof(claim_id, up_to=window_end):
                    return PredicateResult(
                        name=self.name,
                        ok=False,
                        reason=(
                            "Timely(OPTIMISTIC): fraud proof recorded in state "
                            "for this claim within the dispute window."
                        ),
                        metadata={
                            **metadata,
                            "claim_id": claim_id,
                            "fraud_proof": True,
                        },
                    )

            # 6) Optional freshness bound (max_age)
            max_age_result = _check_max_age(metadata)
            if max_age_result is not None:
                return max_age_result

            return PredicateResult(
                name=self.name,
                ok=True,
                metadata={
                    **metadata,
                    "fraud_proof": False,
                    "pending": False,
                    "note": (
                        "Optimistic: dispute window has passed, TTL (if any) and "
                        "optional max_age are satisfied, no fraud proof flagged "
                        "in this experiment."
                    ),
                },
            )

        # ------------------------------------------------------------
        # Case 2: HTLC – hash-time locked contracts (time_lock)
        # ------------------------------------------------------------
        if family == VerificationFamily.HTLC:
            assert isinstance(ctx.e, HTLCEvidence)
            ev = ctx.e

            # Parse TTL (optional) and time_lock (typically required)
            try:
                ttl_int = _parse_ttl()
            except ValueError as exc:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=f"Timely(HTLC): {exc}",
                    metadata={"now": now},
                )

            time_lock_raw = ev.time_lock
            time_lock_int: Optional[int]
            if time_lock_raw is None:
                # In a realistic HTLC, a timelock is essential.
                # If neither TTL nor time_lock exists, we cannot enforce Timely.
                if ttl_int is None:
                    return PredicateResult(
                        name=self.name,
                        ok=False,
                        reason=(
                            "Timely(HTLC): both m.meta.ttl and ev.time_lock "
                            "are missing; HTLC semantics require a timelock."
                        ),
                        metadata={"now": now},
                    )
                time_lock_int = None
            else:
                try:
                    time_lock_int = int(time_lock_raw)
                except (TypeError, ValueError):
                    return PredicateResult(
                        name=self.name,
                        ok=False,
                        reason=(
                            f"Timely(HTLC): invalid time_lock value={time_lock_raw!r}."
                        ),
                        metadata={"now": now},
                    )

            # Consistency: if both TTL and timelock exist, timelock should not exceed TTL
            if ttl_int is not None and time_lock_int is not None and time_lock_int > ttl_int:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        "Timely(HTLC): time_lock is beyond TTL "
                        f"(time_lock={time_lock_int} > ttl={ttl_int}); "
                        "configuration is inconsistent."
                    ),
                    metadata={
                        "now": now,
                        "ttl": ttl_int,
                        "time_lock": time_lock_int,
                        "timelock_outside_ttl": True,
                    },
                )

            # Effective deadline is the minimum of {TTL, time_lock} that are set
            deadlines = [d for d in (ttl_int, time_lock_int) if d is not None]
            assert deadlines, "At least one of TTL or time_lock must be present here."
            effective_deadline = min(deadlines)

            if now > effective_deadline:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        "Timely(HTLC): timelock/TTL expired "
                        f"(now={now} > effective_deadline={effective_deadline})."
                    ),
                    metadata={
                        "now": now,
                        "ttl": ttl_int,
                        "time_lock": time_lock_int,
                        "effective_deadline": effective_deadline,
                        "expired": True,
                    },
                )

            metadata: Dict[str, Any] = {
                "now": now,
                "ttl": ttl_int,
                "time_lock": time_lock_int,
                "effective_deadline": effective_deadline,
            }

            # Optional max_age for HTLC as well
            max_age_result = _check_max_age(metadata)
            if max_age_result is not None:
                return max_age_result

            return PredicateResult(
                name=self.name,
                ok=True,
                metadata={
                    **metadata,
                    "expired": False,
                    "note": (
                        "HTLC: within timelock/TTL horizon, optional max_age satisfied."
                    ),
                },
            )

        # ------------------------------------------------------------
        # Case 3: MPC / ZK LC / Native LC – TTL + optional max_age only
        # ------------------------------------------------------------
        if family in {
            VerificationFamily.MPC_TSS,
            VerificationFamily.ZK_LIGHT_CLIENT,
            VerificationFamily.NATIVE_LIGHT_CLIENT,
        }:
            try:
                ttl_int = _parse_ttl()
            except ValueError as exc:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=f"Timely({family.value}): {exc}",
                    metadata={"now": now},
                )

            # For these families, once Timely is in the pipeline, we require an explicit TTL.
            if ttl_int is None:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        f"Timely({family.value}): m.meta.ttl is missing; "
                        "Timely semantics require an explicit TTL when enabled."
                    ),
                    metadata={"now": now},
                )

            if now > ttl_int:
                return PredicateResult(
                    name=self.name,
                    ok=False,
                    reason=(
                        f"Timely({family.value}): message TTL expired "
                        f"(now={now} > ttl={ttl_int})."
                    ),
                    metadata={"now": now, "ttl": ttl_int},
                )

            metadata: Dict[str, Any] = {"now": now, "ttl": ttl_int}

            # Optional max_age constraint
            max_age_result = _check_max_age(metadata)
            if max_age_result is not None:
                return max_age_result

            return PredicateResult(
                name=self.name,
                ok=True,
                metadata={
                    **metadata,
                    "note": (
                        f"{family.value}: TTL and optional max_age constraints "
                        "are satisfied."
                    ),
                },
            )

        # ------------------------------------------------------------
        # Case 4: any other family – Timely enabled but not defined
        # ------------------------------------------------------------
        return PredicateResult(
            name=self.name,
            ok=False,
            reason=(
                f"Timely: no semantics implemented for family={family.value}, "
                "but Timely was enabled in the pipeline."
            ),
            metadata={"now": now},
        )
