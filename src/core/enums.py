# src/enums.py
from __future__ import annotations

from enum import Enum


class VerificationFamily(str, Enum):
    """
    Mechanism families in our unified semantics.
    This matches the categories in the thesis.
    """
    MPC_TSS = "mpc_tss"
    OPTIMISTIC = "optimistic"
    ZK_LIGHT_CLIENT = "zk_light_client"
    NATIVE_LIGHT_CLIENT = "native_light_client"

    HTLC = "htlc"
    APPLICATION_WORKFLOW = "application_workflow"


class PredicateName(str, Enum):
    """
    Canonical names of the unified predicates (Section 4.2.1–4.3.2 in the paper).

    Evidence layer:
      Authentic(e), HdrRef(e), DomainBind(m,e), ContextOK(e)

    Runtime layer:
      Contain(m, hs), Final(e/hs), Unique(m), Timely(m,e), Order(m),
      DomainOK(m)
    """

    # ---- Evidence-layer predicates ----
    AUTHENTIC = "Authentic"
    HDR_REF = "HdrRef"
    DOMAIN_BIND = "DomainBind"
    CONTEXT_OK = "ContextOK"

    # ---- Runtime-layer predicates ----
    CONTAIN = "Contain"
    FINAL = "Final"
    UNIQUE = "Unique"
    TIMELY = "Timely"
    ORDER = "Order"
    DOMAIN_OK = "DomainOK"
