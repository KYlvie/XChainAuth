# src/experiments/config.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Optional

from core.models import Header
from core.state import InMemoryStateManager


@dataclass
class SimulationChain:
    """
    Minimal in-memory simulation of a source chain S used in experiments.

    This is *not* a consensus model. It only records:
        - headers:    mapping height -> Header
        - finality:   a set of heights that are considered "final"

    The idea is that threat scenarios can:
        - call add_header(h, is_final=...) to populate the mirror, and
        - let predicates query these views via ExperimentalStateManager.
    """
    chain_id: str
    _headers: Dict[int, Header] = field(default_factory=dict)
    _final_heights: set[int] = field(default_factory=set)

    def add_header(self, header: Header, *, is_final: bool = True) -> None:
        """
        Insert a header into the simulated chain.

        By default, the newly added header is marked as final. To simulate
        reorgs or non-final segments, threat scenarios can pass is_final=False.
        """
        if header.chain_id != self.chain_id:
            raise ValueError(
                f"Header.chain_id={header.chain_id} "
                f"does not match SimulationChain.chain_id={self.chain_id}"
            )
        self._headers[header.height] = header
        if is_final:
            self._final_heights.add(header.height)

    def get_header(self, height: int) -> Optional[Header]:
        """Return the header at a given height, or None if unknown."""
        return self._headers.get(height)

    def is_final(self, height: int) -> bool:
        """Return True iff the given height is currently marked as final."""
        return height in self._final_heights

    @property
    def tip_height(self) -> Optional[int]:
        """Return the maximum height we have seen on this simulated chain."""
        if not self._headers:
            return None
        return max(self._headers.keys())


class ExperimentalStateManager(InMemoryStateManager):
    """
    Experimental StateManager

    It extends InMemoryStateManager with a mapping:

        chain_id -> SimulationChain

    so that predicates can read source-chain views via:

        - state.get_header_view(chain_id, height)
        - state.is_final_header(header)

    while still reusing all the generic destination-side evidenceLayer bookkeeping
    (seen messages, per-route ordering, routing policy, inflight set, etc.).
    """

    def __init__(self) -> None:
        super().__init__()
        # Simulated source chains: chain_id -> SimulationChain
        self._chains: Dict[str, SimulationChain] = {}

    # ------------------------------------------------------------------
    # Source-chain mirror API
    # ------------------------------------------------------------------
    def attach_chain(self, chain: SimulationChain) -> None:
        """
        Register a simulated chain.

        Typically called once from the main, e.g.:

            src_chain = SimulationChain("chain-A")
            src_chain.add_header(...)

            state.attach_chain(src_chain)
        """
        self._chains[chain.chain_id] = chain

    def get_chain(self, chain_id: str) -> Optional[SimulationChain]:
        """Return the SimulationChain for a given chain_id, if any."""
        return self._chains.get(chain_id)

    def get_header_view(self, chain_id: str, height: int) -> Optional[Header]:
        """
        Override the generic header-view API to read from SimulationChain.

        Predicates such as Final/Contain call this method to obtain the
        source header hs := HdrRef(e) as seen by the experimental mirror.
        """
        chain = self._chains.get(chain_id)
        if chain is None:
            return None
        return chain.get_header(height)

    def is_final_header(self, header: Header) -> bool:
        """
        Override finality logic to delegate to SimulationChain.

        If we have a simulated chain for header.chain_id, finality is read
        from that chain; otherwise we conservatively treat the header as
        non-final.
        """
        chain = self._chains.get(header.chain_id)
        if chain is None:
            # No mirror for this chain → unknown finality → treat as non-final
            return False
        return chain.is_final(header.height)
