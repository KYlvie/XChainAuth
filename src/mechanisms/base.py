# src/mechanisms/base.py
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Dict, Tuple

from core.enums import VerificationFamily
from core.models import Message
from core.evidence import Evidence
from core.state import StateManager


class Mechanism(ABC):
    """
    抽象的跨链机制接口。

    每个 family 的实现负责：
      - 知道自己属于哪个 VerificationFamily
      - 知道如何从源链上的“应用事件”构造统一的 (Message, Evidence)
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
        从源链上的应用事件构造 (Message, Evidence)。

        参数：
          - src_chain_id, dst_chain_id: 源 / 目的链 ID
          - app_event: “应用事件”，格式由具体 family 自己约定
          - state: StateManager（可以在里面登记 header、finality 等）
          - extra: family 特有的旋钮 / 参数（可选）

        返回：
          - m: 统一的 Message 模型
          - e: family 特有的 Evidence 子类
        """
        raise NotImplementedError

    @staticmethod
    def _canonical_json(obj: Any) -> str:
        data = obj
        if hasattr(obj, "model_dump"):
            data = obj.model_dump(mode="json")
        return json.dumps(data, sort_keys=True, separators=(",", ":"))