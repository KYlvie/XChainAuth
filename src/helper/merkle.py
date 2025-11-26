# helper/merkle.py
from __future__ import annotations

import hashlib
from typing import List, Tuple


def _normalize_hex(s: str) -> str:
    """
    Normalize and validate a hex-encoded string.

    - Accepts optional '0x' / '0X' prefix.
    - Strips surrounding whitespace.
    - Raises ValueError if the remaining characters are not valid hex.

    In our model, we *intend* all Merkle inputs (leaves, siblings, root)
    to be 32-byte SHA-256 digests encoded as hex (64 hex chars), but we
    do not hard-enforce the length here to keep the helper generic.
    """
    if not isinstance(s, str):
        raise ValueError(f"Expected hex string, got {type(s).__name__}: {s!r}")

    s = s.strip()
    if s.startswith(("0x", "0X")):
        s = s[2:]

    # bytes.fromhex will raise if s is not valid hex.
    try:
        bytes.fromhex(s)
    except ValueError as exc:
        raise ValueError(f"Not a valid hex string: {s!r}") from exc

    return s


def _hash_pair_hex(a: str, b: str) -> str:
    """
    Hash the concatenation of two hex-encoded hashes and return a hex digest.

    a, b:
        Hex-encoded hashes (typically 32-byte SHA-256 digests).

    For simplicity, we concatenate in lexicographic order (min(a,b) || max(a,b)),
    which avoids having to carry an explicit "left/right" direction bit in the
    proof. This is not how Bitcoin or Ethereum do it, but it is a common and
    well-defined simplification for experiments.
    """
    a_hex = _normalize_hex(a)
    b_hex = _normalize_hex(b)

    if a_hex <= b_hex:
        left, right = a_hex, b_hex
    else:
        left, right = b_hex, a_hex

    return hashlib.sha256(
        bytes.fromhex(left) + bytes.fromhex(right)
    ).hexdigest()


def build_merkle_tree(leaves: List[str]) -> Tuple[str, List[List[str]]]:
    """
    Build a simple binary Merkle tree from already-hashed leaves.

    Input:
        leaves: list of hex-encoded hashes (e.g. sha256(m).hexdigest()).

    Output:
        - root: Merkle root (hex string)
        - proofs: a list of proof lists, where proofs[i] is the list of
          sibling hashes needed to recompute the root starting from
          leaves[i].

    Notes:
        - We do *not* hash the leaves again here; callers are expected to
          pre-hash their messages or headers to 32-byte SHA-256 digests
          (or another hash) and pass hex strings.
        - When there is an odd number of nodes at a level, the last node
          is paired with itself (standard "leaf duplication" trick).
    """
    if not leaves:
        raise ValueError("Cannot build Merkle tree with no leaves")

    # Normalize all leaves to clean hex once, so later operations do not
    # encounter malformed strings.
    level = [_normalize_hex(x) for x in leaves]
    indices = list(range(len(level)))
    proofs: List[List[str]] = [[] for _ in range(len(level))]

    while len(level) > 1:
        next_level: List[str] = []
        next_indices: List[int] = []

        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                left, right = level[i], level[i + 1]
                parent = _hash_pair_hex(left, right)
                proofs[indices[i]].append(right)
                proofs[indices[i + 1]].append(left)
            else:
                # Odd count: pair the last node with itself
                left = level[i]
                parent = _hash_pair_hex(left, left)
                proofs[indices[i]].append(left)

            next_level.append(parent)
            next_indices.append(indices[i])

        level = next_level
        indices = next_indices

    root = level[0]
    return root, proofs


def verify_merkle_proof(leaf: str, proof: List[str], expected_root: str) -> bool:
    """
    Verify whether a leaf + its sibling list recomputes the expected Merkle root.

    All arguments (leaf, each sibling in proof, and expected_root) are expected
    to be hex-encoded hashes (optionally with a '0x' prefix). The exact same
    pair-hashing rule as _hash_pair_hex is used, i.e., lexicographic ordering
    of the two children before concatenation.

    This corresponds to the following iterative procedure:

        h = leaf
        for sib in proof:
            h = H( min(h,sib) || max(h,sib) )
        return (h == expected_root)
    """
    h = _normalize_hex(leaf)
    root = _normalize_hex(expected_root)

    for sib in proof:
        h = _hash_pair_hex(h, sib)

    return h == root
