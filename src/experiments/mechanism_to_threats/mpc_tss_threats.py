# experiments/mpc_tss_threats.py
from __future__ import annotations

import hmac
from typing import List, Tuple

from core.enums import VerificationFamily
from core.models import Message, MessageMeta, Header
from core.evidence import MPCEvidence, CommitteeAttestation
from core.state import StateManager, make_default_state_manager
from experiments.threats_base import ThreatScenario, ThreatId, Label
from mechanisms.mpc_tss import MpcTssMechanism


def make_hmac_signature(secret: bytes, m: Message, h: Header) -> str:
    """
    使用和 HmacCommitteeVerifier 完全相同的 canonical 序列化规则，
    对 (m, h) 做 HMAC-SHA256 签名。

    这样，Authentic(e) 谓词可以用同一个 helper 进行重放验证。
    """
    from helper.crypto import HmacCommitteeVerifier as HV

    data = HV._canonical_bytes(m, h)  # type: ignore[attr-defined]
    return hmac.new(secret, data, digestmod="sha256").hexdigest()


class MpcTssThreat1InclusionScenario(ThreatScenario):
    description = """
    Threat1: Inclusion failure (for MPC_TSS, 现实语义版).

    在我们的统一语义下，Inclusion failure 的含义是：
      - 目的链 D 接受了一条消息 m_attack；
      - 但在真实的源链状态中，m_attack 从未被正确记录／执行；
      - 换言之，e 只是“委员会声称它看到了 m_attack 与某个 h_s”，
        而不是“m_attack 在 source state 里可验证地存在”。

    对于 MPC/TSS notary 家族，这种攻击在结构上是【不可检测】的：
      - SAFE 样本：真实事件 m_safe，诚实委员会生成 (m_safe, e_safe)；
      - ATTACK 样本：伪造事件 m_attack，从未出现在源链，
        但委员会仍然对 (m_attack, h_s) 产生合法签名 e_att。

    对这两条样本：
      - Authentic(e)     → True  (合法阈值签名)
      - HdrRef(e)        → True  (header 引用存在)
      - ContextOK(e)     → True  (我们模型里 payload 绑定了 {nonce,seq,channel,timestamp})
      - Contain(m, σ)    → 结构性不支持 (MPC 家族没有包含性能力)
      - Final(h_s)       → 结构性不支持
      - 其余 runtime 谓词（Unique/Timely/...）同样不支持

    因此，从目的链 Authorizer 的视角，SAFE 与 ATTACK 的谓词向量完全一致，
    这正是我们在第 5–6 章中要论证的：MPC/TSS 无法在语义上防御 Inclusion failure。
    """

    threat_id = ThreatId.T1_INCLUSION
    family = VerificationFamily.MPC_TSS

    def __init__(
        self,
        committee_id: str = "committee-1",
        secret_key: bytes = b"super-secret-key",
    ) -> None:
        self.committee_id = committee_id
        self.secret_key = secret_key

        # “诚实机制”实例（safe 样本通过它构造）
        self.mech = MpcTssMechanism(
            committee_id=self.committee_id,
            secret_key=self.secret_key,
        )

    def generate_trace(
        self,
        state: make_default_state_manager(VerificationFamily.MPC_TSS),  # 实验里我们知道是这个实现
        kappa: dict | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, MPCEvidence, Label]]:
        # ======================================================================
        # 1) SAFE 样本：真实事件 m_safe，诚实 notary 生成 e_safe
        # ======================================================================
        safe_event = {
            "payload": {"amount": 100, "to": "bob"},
            "seq": 1,
            "timestamp": 1_700_000_000,
            "channel": "chan-1",
            "height": 100,
            # 注意：现实版 notary 不会提供 Merkle proof，
            # 因此我们不再使用 other_leaves，也不构造 leaf/proof。
        }
        m_safe, e_safe = self.mech.build_message_and_evidence(
            src_chain_id="chain-A",
            dst_chain_id="chain-B",
            app_event=safe_event,
            state=state,
        )

        # ======================================================================
        # 2) ATTACK 样本：inclusion failure
        # ======================================================================
        # 2.1 先对“另一个真实事件” m_other 诚实生成 (m_other, e_other)，
        #     主要目的是获得一个 plausibly-valid header h_s。
        other_event = {
            "payload": {"amount": 999, "to": "mallory"},
            "seq": 2,
            "timestamp": 1_700_000_001,
            "channel": "chan-1",
            "height": 100,  # 同一个高度，方便对比
        }
        m_other, e_other = self.mech.build_message_and_evidence(
            src_chain_id="chain-A",
            dst_chain_id="chain-B",
            app_event=other_event,
            state=state,
        )

        # 2.2 构造一个“并未真正发生在源链上的”攻击消息 m_attack
        meta_attack = MessageMeta(
            seq=3,
            ttl=None,
            timestamp=1_700_000_002,
            channel="chan-1",
        )
        m_attack = Message(
            src="chain-A",
            dst="chain-B",
            payload={"amount": 42, "to": "alice"},
            meta=meta_attack,
        )

        # 2.3 复用 e_other 的 header（假装这是一个“canonical”视图），
        #     但重新对 (m_attack, header_for_attack) 生成一个合法 signature。
        header_for_attack = e_other.header
        sig_attack = make_hmac_signature(self.secret_key, m_attack, header_for_attack)

        att_attack = CommitteeAttestation(
            committee_id=self.committee_id,
            signature=sig_attack,
            payload={
                "nonce": meta_attack.seq,
                "seq": meta_attack.seq,
                "channel": meta_attack.channel,
                "timestamp": meta_attack.timestamp,
            },
        )

        e_att = MPCEvidence(
            family=VerificationFamily.MPC_TSS,
            attestation=att_attack,
            header=header_for_attack,
        )

        # 从目的链的 Authorizer 视角：
        #   - (m_safe, e_safe) 与 (m_attack, e_att) 的所有可见证据形状
        #     与谓词结果完全一致；
        #   - 唯一的区别是“m_attack 从未出现在源链状态里”，但由于 MPC
        #     家族没有 Contain/Final 能力，这个事实不可判定。
        return [
            (m_safe, e_safe, Label.SAFE),
            (m_attack, e_att, Label.ATTACK),
        ]

# experiments/mpc_tss_threats.py 末尾附加一个“弱攻击者可防护”的版本

class MpcTssThreat1TamperScenario(ThreatScenario):
    description = """
    Threat1（子类）：传输路径篡改消息，但攻击者不能让委员会重新签名。

    场景语义：
      - 源链上真实发生了事件 m_safe，诚实委员会对 (m_safe, h_s) 生成 e_safe；
      - 在从 S → D 传消息的过程中，攻击者篡改了消息体成 m_tampered
        （例如改 amount, to 等），但仍然附带原来的 e_safe；
      - 目的链 Authorizer 收到的是 (m_tampered, e_safe)。

    对于这个子场景：
      - SAFE: (m_safe, e_safe)
      - ATTACK: (m_tampered, e_safe)

    由于 MPC 家族的 Authentic(e) 会对 (m, h_s, signature) 做一次重新验签：
      - SAFE 样本：verify(m_safe, h_s, sig_safe) = True
      - ATTACK 样本：verify(m_tampered, h_s, sig_safe) = False

    所以：
      - SAFE:  Authentic = True
      - ATTACK: Authentic = False

    换句话说，这一类 “只篡改 m、不能重新签名” 的 inclusion failure，
    在 MPC/TSS 家族下是可以被 Authentic 谓词防护掉的。
    """

    threat_id = ThreatId.T1_TAMPER   # 你也可以以后在 enum 里加一个专门的 T1_TAMPER
    family = VerificationFamily.MPC_TSS

    def __init__(
        self,
        committee_id: str = "committee-1",
        secret_key: bytes = b"super-secret-key",
    ) -> None:
        self.committee_id = committee_id
        self.secret_key = secret_key
        self.mech = MpcTssMechanism(
            committee_id=self.committee_id,
            secret_key=self.secret_key,
        )

    def generate_trace(
        self,
        state: make_default_state_manager(VerificationFamily.MPC_TSS),
        kappa: dict | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, MPCEvidence, Label]]:
        # 1) 正常的 safe 样本：诚实桥生成 (m_safe, e_safe)
        safe_event = {
            "payload": {"amount": 100, "to": "bob"},
            "seq": 10,
            "timestamp": 1_700_000_100,
            "channel": "chan-2",
            "height": 200,
        }
        m_safe, e_safe = self.mech.build_message_and_evidence(
            src_chain_id="chain-A",
            dst_chain_id="chain-B",
            app_event=safe_event,
            state=state,
        )

        # 2) 攻击者在“线路上”篡改了消息体，但拿不到新的委员会签名
        meta_tampered = MessageMeta(
            seq=m_safe.meta.seq,
            ttl=m_safe.meta.ttl,
            timestamp=m_safe.meta.timestamp,
            channel=m_safe.meta.channel,
        )
        m_tampered = Message(
            src=m_safe.src,
            dst=m_safe.dst,
            # 篡改 payload（例如金额和收款地址）
            payload={"amount": 9999, "to": "mallory"},
            meta=meta_tampered,
        )

        # 关键点：攻击者仍然附带的是 “原来的” e_safe（同一个 signature）
        e_tampered = e_safe

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_tampered, e_tampered, Label.ATTACK),
        ]

class MpcTssThreat2DomainMisbindScenario(ThreatScenario):
    description = """
    Threat2: Domain misbinding (T2_DOMAIN_MISBIND).

    Intuition:
      - The committee legitimately signs a message m_safe for a permitted
        route (src="chain-A", dst="chain-B", channel="chan-1").
      - An attacker reuses the same evidence e_safe but rewrites the
        routing domain of the message into an *unpermitted* route,
        e.g. dst="chain-C" or channel="evil-chan".
      - From the committee’s point of view, this is still the same
        signature over (m_safe, h_s). But the Authorizer on D must
        enforce routing policy via DomainOK(m, σ_runtime).

    SAFE:
      - (m_safe, e_safe) where Route(m_safe) = ("chain-A", "chain-B", "chan-1")
        and this route is whitelisted in StateManager.set_allowed_routes.

    ATTACK:
      - (m_attack, e_safe) reusing the same signature and header,
        but Route(m_attack) = ("chain-A", "chain-C", "chan-1") which is
        not in the whitelist.

    Expected predicate vector (hardened semantics):
      - Authentic(e): True  for both samples
      - HdrRef(e):    True  for both
      - ContextOK(e): True  for both
      - DomainOK(m, σ_runtime):
          SAFE   → True  (route is allowed)
          ATTACK → False (route is not allowed)
    """

    threat_id = ThreatId.T2_DOMAIN_MISBIND
    family = VerificationFamily.MPC_TSS

    def __init__(
        self,
        committee_id: str = "committee-1",
        secret_key: bytes = b"super-secret-key",
    ) -> None:
        self.committee_id = committee_id
        self.secret_key = secret_key
        self.mech = MpcTssMechanism(
            committee_id=self.committee_id,
            secret_key=self.secret_key,
        )

    def generate_trace(
        self,
        state: StateManager,
        kappa: dict | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, MPCEvidence, Label]]:
        # SAFE: permitted route (A → B, chan-1)
        safe_event = {
            "payload": {"amount": 50, "to": "bob"},
            "seq": 5,
            "timestamp": 1_700_000_050,
            "channel": "chan-1",
            "height": 101,
        }
        m_safe, e_safe = self.mech.build_message_and_evidence(
            src_chain_id="chain-A",
            dst_chain_id="chain-B",
            app_event=safe_event,
            state=state,
        )

        # ATTACK: reuse evidence but change routing domain to an unallowed dst
        meta_attack = MessageMeta(
            seq=m_safe.meta.seq,
            ttl=m_safe.meta.ttl,
            timestamp=m_safe.meta.timestamp,
            channel=m_safe.meta.channel,
        )
        m_attack = Message(
            src=m_safe.src,
            dst="chain-C",  # not whitelisted by make_experimental_state_manager
            payload=m_safe.payload,
            meta=meta_attack,
        )
        e_attack = e_safe  # same signature / header

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_attack, e_attack, Label.ATTACK),
        ]
class MpcTssThreat3EquivocationScenario(ThreatScenario):
    description = """
    Threat3: Non-final or equivocated evidence (T3_EQUIVOCATION).

    Intuition:
      - The Authorizer on D relies on headers/views of S that are either
        not final yet, or conflict with other equally valid views
        (equivocation, reorgs).
      - For MPC/TSS, the committee does not prove finality; it only
        signs some header h_s. We model a hardened version where D has
        access to a chain mirror via ExperimentalStateManager + SimulationChain.

    SAFE:
      - (m_safe, e_safe) where e_safe.header.height = h_final
        and the SimulationChain marks this height as final.

    ATTACK:
      - (m_attack, e_att) where e_att.header.height = h_nonfinal
        which SimulationChain does *not* mark as final (or marks as
        conflicting).

    Expected hardened semantics:
      - Authentic(e): True for both (committee honestly signs)
      - Final(h_s, σ_chain):
          SAFE   → True  (height is final in SimulationChain)
          ATTACK → False (height is non-final or equivocated)
    """

    threat_id = ThreatId.T3_EQUIVOCATION
    family = VerificationFamily.MPC_TSS

    def __init__(
        self,
        committee_id: str = "committee-1",
        secret_key: bytes = b"super-secret-key",
    ) -> None:
        self.committee_id = committee_id
        self.secret_key = secret_key
        self.mech = MpcTssMechanism(
            committee_id=self.committee_id,
            secret_key=self.secret_key,
        )

    def generate_trace(
        self,
        state: StateManager,
        kappa: dict | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, MPCEvidence, Label]]:
        # We assume ExperimentalStateManager; try to get the attached chain.
        from experiments.config import SimulationChain  # type: ignore

        # SAFE header: height 120 is final
        h_final = Header(
            chain_id="chain-A",
            height=120,
            hash="0xfinal-120",
        )
        # ATTACK header: height 121 exists but is not final
        h_nonfinal = Header(
            chain_id="chain-A",
            height=121,
            hash="0xnonfinal-121",
        )

        # If the state is an ExperimentalStateManager, register headers.
        if hasattr(state, "get_chain") and callable(getattr(state, "get_chain")):
            chain = state.get_chain("chain-A")  # type: ignore[attr-defined]
            if chain is not None:
                chain.add_header(h_final, is_final=True)
                chain.add_header(h_nonfinal, is_final=False)

        # SAFE sample: honest event on a final header
        safe_event = {
            "payload": {"amount": 7, "to": "carol"},
            "seq": 11,
            "timestamp": 1_700_000_120,
            "channel": "chan-3",
            "height": h_final.height,
        }
        m_safe, e_safe = self.mech.build_message_and_evidence(
            src_chain_id="chain-A",
            dst_chain_id="chain-B",
            app_event=safe_event,
            state=state,
        )

        # ATTACK sample: honest committee signs over a non-final header
        attack_event = {
            "payload": {"amount": 8, "to": "dave"},
            "seq": 12,
            "timestamp": 1_700_000_121,
            "channel": "chan-3",
            "height": h_nonfinal.height,
        }
        m_attack, e_att = self.mech.build_message_and_evidence(
            src_chain_id="chain-A",
            dst_chain_id="chain-B",
            app_event=attack_event,
            state=state,
        )

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_attack, e_att, Label.ATTACK),
        ]
class MpcTssThreat4ReplayScenario(ThreatScenario):
    description = """
    Threat4: Replay / double-spend (T4_REPLAY).

    Intuition:
      - An already-authorized message (m, e) is re-submitted to the
        Authorizer on D, without any change to evidence.
      - If the Authorizer does not track MessageKey and enforce Unique(m),
        the same cross-chain transfer may be processed twice.

    SAFE:
      - (m_safe, e_safe) first occurrence; state has not yet seen this key.

    ATTACK:
      - (m_replay, e_replay) identical to (m_safe, e_safe) but evaluated
        after the first one, so Unique(m) should fail.

    Expected hardened semantics:
      - Authentic(e): True in both cases
      - Unique(m, σ_runtime):
          SAFE   → True  (first time)
          ATTACK → False (key already in σ_runtime.seen)
    """

    threat_id = ThreatId.T4_REPLAY
    family = VerificationFamily.MPC_TSS

    def __init__(
        self,
        committee_id: str = "committee-1",
        secret_key: bytes = b"super-secret-key",
    ) -> None:
        self.committee_id = committee_id
        self.secret_key = secret_key
        self.mech = MpcTssMechanism(
            committee_id=self.committee_id,
            secret_key=self.secret_key,
        )

    def generate_trace(
        self,
        state: StateManager,
        kappa: dict | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, MPCEvidence, Label]]:
        # Normal honest event
        event = {
            "payload": {"amount": 123, "to": "bob"},
            "seq": 20,
            "timestamp": 1_700_000_200,
            "channel": "chan-replay",
            "height": 300,
        }
        m_safe, e_safe = self.mech.build_message_and_evidence(
            src_chain_id="chain-A",
            dst_chain_id="chain-B",
            app_event=event,
            state=state,
        )

        # Replay: exactly the same message + evidence, evaluated later
        m_replay = m_safe
        e_replay = e_safe

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_replay, e_replay, Label.ATTACK),
        ]

class MpcTssThreat5TimelinessScenario(ThreatScenario):
    description = """
    Threat5: Timeliness / freshness violation (T5_TIMELINESS).

    Intuition:
      - Messages carry a TTL / freshness budget in meta.ttl.
      - SAFE messages arrive before expiry; ATTACK messages are delivered
        after TTL, but the committee signature is still valid.
      - The Timely(m, e, now) predicate must reject late messages even
        if Authentic(e) succeeds.

    SAFE:
      - (m_safe, e_safe) with TTL sufficiently in the future relative to now.

    ATTACK:
      - (m_late, e_late) with the same TTL, but evaluated at a much
        larger logical time now, so Timely should fail.

    We use a fixed now=1_700_000_999 in the experiment runner.
    """

    threat_id = ThreatId.T5_TIMELINESS
    family = VerificationFamily.MPC_TSS

    def __init__(
        self,
        committee_id: str = "committee-1",
        secret_key: bytes = b"super-secret-key",
    ) -> None:
        self.committee_id = committee_id
        self.secret_key = secret_key
        self.mech = MpcTssMechanism(
            committee_id=self.committee_id,
            secret_key=self.secret_key,
        )

    def generate_trace(
        self,
        state: StateManager,
        kappa: dict | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, MPCEvidence, Label]]:
        # SAFE: ttl is in the future relative to now
        safe_meta = {
            "payload": {"amount": 10, "to": "bob"},
            "seq": 30,
            "timestamp": 1_700_000_900,
            "channel": "chan-time",
            "height": 400,
        }
        m_safe, e_safe = self.mech.build_message_and_evidence(
            src_chain_id="chain-A",
            dst_chain_id="chain-B",
            app_event=safe_meta,
            state=state,
        )
        # Manually set TTL for the SAFE sample
        m_safe.meta.ttl = 200  # e.g. 200 units after timestamp

        # ATTACK: same structure but TTL too small so it's expired
        m_late = m_safe.copy(deep=True)
        # Suppose TTL was only 10 units; with now fixed, this is expired
        m_late.meta.ttl = 10

        # Evidence can be reused (committee does not know about TTL semantics)
        e_late = e_safe

        return [
            (m_safe, e_safe, Label.SAFE),
            (m_late, e_late, Label.ATTACK),
        ]
class MpcTssThreat6OrderingScenario(ThreatScenario):
    description = """
    Threat6: Channel / workflow ordering violation (T6_ORDERING).

    Intuition:
      - Many bridge protocols require per-channel in-order delivery:
        seq numbers on (src, dst, chan) must be strictly increasing.
      - SAFE: messages follow the expected order (…, 1, 2).
      - ATTACK: an out-of-order or duplicated sequence number is
        delivered (e.g., seq=1 again after 2), and Order(m, σ_runtime)
        must reject it.

    SAFE:
      - two messages on the same route with seq=1 then seq=2

    ATTACK:
      - a third message reusing seq=1 (or seq=1.5 < next_seq),
        provoking an Order violation.
    """

    threat_id = ThreatId.T6_ORDERING
    family = VerificationFamily.MPC_TSS

    def __init__(
        self,
        committee_id: str = "committee-1",
        secret_key: bytes = b"super-secret-key",
    ) -> None:
        self.committee_id = committee_id
        self.secret_key = secret_key
        self.mech = MpcTssMechanism(
            committee_id=self.committee_id,
            secret_key=self.secret_key,
        )

    def generate_trace(
        self,
        state: StateManager,
        kappa: dict | None = None,
        seed: int | None = None,
    ) -> List[Tuple[Message, MPCEvidence, Label]]:
        route = ("chain-A", "chain-B", "chan-order")

        # SAFE #1: seq = 1
        ev1 = {
            "payload": {"amount": 1, "to": "alice"},
            "seq": 1,
            "timestamp": 1_700_001_000,
            "channel": route[2],
            "height": 500,
        }
        m1, e1 = self.mech.build_message_and_evidence(
            src_chain_id=route[0],
            dst_chain_id=route[1],
            app_event=ev1,
            state=state,
        )

        # SAFE #2: seq = 2  (in-order)
        ev2 = {
            "payload": {"amount": 2, "to": "bob"},
            "seq": 2,
            "timestamp": 1_700_001_001,
            "channel": route[2],
            "height": 501,
        }
        m2, e2 = self.mech.build_message_and_evidence(
            src_chain_id=route[0],
            dst_chain_id=route[1],
            app_event=ev2,
            state=state,
        )

        # ATTACK: re-use seq = 1 again (out-of-order / duplicate)
        meta_attack = MessageMeta(
            seq=1,  # already consumed
            ttl=None,
            timestamp=1_700_001_002,
            channel=route[2],
        )
        m_attack = Message(
            src=route[0],
            dst=route[1],
            payload={"amount": 3, "to": "mallory"},
            meta=meta_attack,
        )
        # Committee signs this honestly over some header (re-using header from e2)
        sig_attack = make_hmac_signature(self.secret_key, m_attack, e2.header)
        att_attack = CommitteeAttestation(
            committee_id=self.committee_id,
            signature=sig_attack,
            payload={
                "nonce": meta_attack.seq,
                "seq": meta_attack.seq,
                "channel": meta_attack.channel,
                "timestamp": meta_attack.timestamp,
            },
        )
        e_attack = MPCEvidence(
            family=VerificationFamily.MPC_TSS,
            attestation=att_attack,
            header=e2.header,
        )

        return [
            (m1, e1, Label.SAFE),
            (m2, e2, Label.SAFE),
            (m_attack, e_attack, Label.ATTACK),
        ]



# 以后你写完 T2–T6，可以统一注册在这里：
SCENARIOS_MPC_TSS: dict[ThreatId, ThreatScenario] = {
    ThreatId.T1_INCLUSION: MpcTssThreat1InclusionScenario(),
    ThreatId.T1_TAMPER:    MpcTssThreat1TamperScenario(),
    ThreatId.T2_DOMAIN_MISBIND: MpcTssThreat2DomainMisbindScenario(),
    ThreatId.T3_EQUIVOCATION:   MpcTssThreat3EquivocationScenario(),
    ThreatId.T4_REPLAY:         MpcTssThreat4ReplayScenario(),
    ThreatId.T5_TIMELINESS:     MpcTssThreat5TimelinessScenario(),
    ThreatId.T6_ORDERING:       MpcTssThreat6OrderingScenario(),
}
