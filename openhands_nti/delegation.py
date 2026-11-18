"""Merkle delegation chain: build and verify inclusion proofs.

The construction matches the NTI reference implementation byte-for-byte so a
receipt produced here verifies against the same tooling:

* leaf  ``sha256(b"nti-delegation-leaf-v1:" || canonical_json(record))``
* node  ``sha256(b"nti-delegation-node-v1:" || left || right)``
* odd   the final node is promoted unchanged (RFC 6962), never duplicated

A delegation record authorizes a *capability* held by a *subject* DID. The
guardrail proves, for each action, that a record granting that capability is
included in the chain rooted at ``delegation_chain_root``.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Any

from openhands_nti.canonical import canonical_json
from openhands_nti.errors import DelegationError

DOMAIN_LEAF = b"nti-delegation-leaf-v1:"
DOMAIN_NODE = b"nti-delegation-node-v1:"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(record: dict[str, Any]) -> bytes:
    return sha256(DOMAIN_LEAF + canonical_json(record))


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(DOMAIN_NODE + left + right)


def merkle_root(leaves: list[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Hash. The odd node is promoted, never duplicated."""
    if not leaves:
        raise DelegationError("delegation chain is empty")
    level = list(leaves)
    while len(level) > 1:
        nxt = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return level[0]


@dataclass(frozen=True)
class Sibling:
    position: str  # "left", "right" or "promoted"
    digest: bytes

    def to_json(self) -> dict[str, str]:
        return {"position": self.position, "sha256": self.digest.hex()}


def inclusion_proof(leaves: list[bytes], index: int) -> list[Sibling]:
    """Return the sibling path proving ``leaves[index]`` is in the tree."""
    if not leaves:
        raise DelegationError("delegation chain is empty")
    if not 0 <= index < len(leaves):
        raise DelegationError(f"leaf index {index} out of range for {len(leaves)} leaves")

    proof: list[Sibling] = []
    level = list(leaves)
    idx = index
    while len(level) > 1:
        if idx % 2 == 1:
            proof.append(Sibling("left", level[idx - 1]))
        elif idx + 1 < len(level):
            proof.append(Sibling("right", level[idx + 1]))
        else:
            # Odd tail: this node is promoted unchanged.
            proof.append(Sibling("promoted", level[idx]))
        nxt = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        idx //= 2
        level = nxt
    return proof


def fold_proof(leaf: bytes, siblings: list[Sibling]) -> bytes:
    """Fold an inclusion proof into a candidate root."""
    acc = leaf
    for sibling in siblings:
        if sibling.position == "left":
            acc = node_hash(sibling.digest, acc)
        elif sibling.position == "right":
            acc = node_hash(acc, sibling.digest)
        elif sibling.position == "promoted":
            if sibling.digest != acc:
                raise DelegationError("promoted sibling does not equal the accumulator")
        else:
            raise DelegationError(f"unknown sibling position: {sibling.position!r}")
    return acc


def _matches(record: dict[str, Any], *, subject: str, capability: str) -> bool:
    if record.get("subject") != subject:
        return False
    scope = record.get("scope")
    if isinstance(scope, str):
        return scope == capability
    if isinstance(scope, list):
        return capability in scope
    return False


def select_record(
    chain: list[dict[str, Any]], *, subject: str, capability: str
) -> int:
    """Index of the first record authorizing ``capability`` for ``subject``."""
    for index, record in enumerate(chain):
        if _matches(record, subject=subject, capability=capability):
            return index
    raise DelegationError(
        f"no delegation record grants capability {capability!r} to {subject!r}"
    )


@dataclass(frozen=True)
class DelegationProof:
    """A verifiable inclusion proof for one delegation record."""

    leaf_index: int
    leaf_sha256: bytes
    siblings: tuple[Sibling, ...]
    root_sha256: bytes

    def to_json(self) -> dict[str, Any]:
        return {
            "hash_algorithm": "sha256",
            "leaf_encoding": 'sha256(b"nti-delegation-leaf-v1:" || canonical_json(record))',
            "node_encoding": 'sha256(b"nti-delegation-node-v1:" || left || right)',
            "odd_node_rule": "last node promoted unchanged, never duplicated (RFC 6962)",
            "leaf_index": self.leaf_index,
            "leaf_sha256": self.leaf_sha256.hex(),
            "siblings": [s.to_json() for s in self.siblings],
            "root_sha256": self.root_sha256.hex(),
        }


def build_proof(
    chain: list[dict[str, Any]], *, subject: str, capability: str
) -> DelegationProof:
    """Build the inclusion proof for the record authorizing ``capability``."""
    index = select_record(chain, subject=subject, capability=capability)
    leaves = [leaf_hash(record) for record in chain]
    root = merkle_root(leaves)
    siblings = inclusion_proof(leaves, index)
    return DelegationProof(
        leaf_index=index,
        leaf_sha256=leaves[index],
        siblings=tuple(siblings),
        root_sha256=root,
    )


def verify_proof(chain: list[dict[str, Any]], proof: DelegationProof) -> bool:
    """Verify a proof folds to the chain's recomputed root."""
    leaves = [leaf_hash(record) for record in chain]
    try:
        root = merkle_root(leaves)
    except DelegationError:
        return False
    if root != proof.root_sha256:
        return False
    folded = fold_proof(proof.leaf_sha256, list(proof.siblings))
    return folded == root
