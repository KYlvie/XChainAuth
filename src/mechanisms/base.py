import json
from abc import abstractmethod, ABC
from typing import Any, Tuple, Dict

from core.enums import VerificationFamily
from core.evidence import Evidence
from core.models import Message
from core.state import StateManager


class Mechanism(ABC):
    """
    Abstract interface for all cross-chain mechanism families.

    Each mechanism implementation is responsible for:
      - Declaring which VerificationFamily it belongs to;
      - Knowing how to translate a source-chain “application event” into the
        unified (Message, Evidence) pair used by the Authorizer pipeline.

    The goal of this interface is to normalize the shape of cross-chain messages
    across heterogeneous mechanism families (MPC/TSS, Optimistic, ZK LC,
    Native LC, HTLC, Workflow, etc.), while allowing each family to embed its
    native cryptographic or protocol-specific evidence structure.
    """

    family: VerificationFamily

    @abstractmethod
    def build_message_and_evidence(
        self,
        *,
        src_chain_id: str,
        dst_chain_id: str,
        app_event: Dict[str, Any],
        state: StateManager,
        extra: Dict[str, Any] | None = None,
    ) -> Tuple[Message, Evidence]:
        """
        Construct the unified (Message, Evidence) pair from a source-chain
        application event.

        Arguments:
          - src_chain_id, dst_chain_id:
                Identifiers of the source/destination chains.
          - app_event:
                Raw application-layer event emitted by the source chain.
                The expected structure is family-specific.
          - state:
                The StateManager instance, which may be updated with runtime
                information such as header views, inflight messages,
                finality information, replay state, etc.
          - extra:
                Optional family-specific configuration knobs.

        Returns:
          - m: A unified Message object that is independent of mechanism family.
          - e: A family-specific Evidence object capturing the cryptographic
               or protocol-level justification carried by this mechanism.
        """
        raise NotImplementedError

    @staticmethod
    def _canonical_json(obj: Any) -> str:
        """
        Serialize an object (including pydantic models) into canonical JSON.
        This is used to ensure deterministic hashing across runs and is shared
        by several mechanism families when deriving commitments or signatures.
        """
        data = obj
        if hasattr(obj, "model_dump"):
            data = obj.model_dump(mode="json")
        return json.dumps(data, sort_keys=True, separators=(",", ":"))
