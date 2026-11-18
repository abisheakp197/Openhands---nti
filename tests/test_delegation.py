"""Merkle delegation proofs: construction, verification, and tamper resistance."""

from __future__ import annotations

import pytest

from openhands_nti.delegation import (
    Sibling,
    build_proof,
    fold_proof,
    leaf_hash,
    merkle_root,
    node_hash,
    select_record,
    verify_proof,
)
from openhands_nti.errors import DelegationError

SUBJECT = "did:example:agent"


def _record(name: str, scope):
    return {"delegation_id": name, "subject": SUBJECT, "scope": scope}


def test_single_leaf_root_is_its_own_hash():
    leaves = [leaf_hash(_record("a", ["cap"]))]
    assert merkle_root(leaves) == leaves[0]


def test_root_changes_with_content():
    a = [leaf_hash(_record("a", ["cap"]))]
    b = [leaf_hash(_record("b", ["cap"]))]
    assert merkle_root(a) != merkle_root(b)


def test_proof_folds_to_root_for_every_index():
    chain = [_record(f"r{i}", ["shell.execute"]) for i in range(7)]
    leaves = [leaf_hash(r) for r in chain]
    root = merkle_root(leaves)
    from openhands_nti.delegation import inclusion_proof

    for index in range(len(leaves)):
        proof = inclusion_proof(leaves, index)
        assert fold_proof(leaves[index], proof) == root


def test_build_and_verify_proof():
    chain = [_record("root", ["file.write"]), _record("leaf", ["shell.execute"])]
    proof = build_proof(chain, subject=SUBJECT, capability="shell.execute")
    assert verify_proof(chain, proof)


def test_proof_fails_when_chain_tampered():
    chain = [_record("root", ["file.write"]), _record("leaf", ["shell.execute"])]
    proof = build_proof(chain, subject=SUBJECT, capability="shell.execute")
    chain[0]["scope"] = ["file.write", "shell.execute"]
    assert not verify_proof(chain, proof)


def test_missing_capability_raises():
    chain = [_record("root", ["file.write"])]
    with pytest.raises(DelegationError):
        build_proof(chain, subject=SUBJECT, capability="shell.execute")


def test_wrong_subject_raises():
    chain = [{"delegation_id": "r", "subject": "did:example:other", "scope": ["x"]}]
    with pytest.raises(DelegationError):
        build_proof(chain, subject=SUBJECT, capability="x")


def test_select_record_prefers_first_match():
    chain = [
        _record("first", ["cap"]),
        _record("second", ["cap"]),
    ]
    assert select_record(chain, subject=SUBJECT, capability="cap") == 0


def test_node_and_leaf_hashes_are_domain_separated():
    # A leaf hash and a node hash over the same bytes must differ.
    record = _record("a", ["cap"])
    assert leaf_hash(record) != node_hash(record["delegation_id"].encode(), b"")


def test_promoted_sibling_must_equal_accumulator():
    leaf = b"leaf"
    bad = [Sibling("promoted", b"something-else")]
    with pytest.raises(DelegationError):
        fold_proof(leaf, bad)
