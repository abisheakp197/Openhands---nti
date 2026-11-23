"""Canonical JSON must byte-match the engine's serde_json encoder."""

from __future__ import annotations

import json

import pytest
import ube_foundation as nti

from openhands_nti.canonical import action_message, canonical_json
from openhands_nti.errors import CanonicalizationError

ACTOR = "did:example:agent"
CAPABILITY = "shell.execute"


def _engine_accepts(payload: object, message: bytes) -> bool:
    engine = nti.TrustEngine()
    key = nti.PqcKeyPair()
    engine.grant(ACTOR, CAPABILITY)
    engine.register_pqc_identity_key(ACTOR, key.get_public_key_bytes())
    request = {
        "id": "req-1",
        "actor": ACTOR,
        "capability": CAPABILITY,
        "action": "bash",
        "input": payload,
        "signature": None,
        "pqc_signature": {
            "algorithm": "ML-DSA-87",
            "signature": list(key.sign_bytes(message)),
        },
        "public_key": None,
        "pqc_public_key": list(key.get_public_key_bytes()),
        "token": None,
        "identity_claim": None,
    }
    verdict = json.loads(engine.evaluate(json.dumps(request)))
    return verdict["decision"] == "Allow"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"command": "ls -la"},
        {"a": {"b": {"c": [1, 2, {"d": None}]}}, "z": True},
        {"unicode": "echo 'héllo → 世界 🚀'"},
        {"path": "/etc/passwd", "nested": {"x": [1, 2, 3]}},
        {"ints": [0, -1, 2**63 - 1, -(2**63)]},
    ],
)
def test_canonical_payload_is_accepted_by_engine(payload):
    message = action_message("req-1", ACTOR, CAPABILITY, "bash", payload)
    assert _engine_accepts(payload, message)


def test_key_order_is_normalized():
    assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert canonical_json({"z": 1, "a": {"y": 2, "b": 3}}) == b'{"a":{"b":3,"y":2},"z":1}'


def test_strings_use_raw_utf8():
    assert canonical_json("héllo") == '"héllo"'.encode()


def test_control_characters_are_escaped():
    assert canonical_json("a\tb\nc") == b'"a\\tb\\nc"'


def test_non_string_key_is_rejected():
    with pytest.raises(CanonicalizationError):
        canonical_json({1: "x"})


def test_oversized_integer_is_rejected():
    with pytest.raises(CanonicalizationError):
        canonical_json(2**64)


def test_non_finite_float_is_rejected():
    with pytest.raises(CanonicalizationError):
        canonical_json(float("inf"))


def test_reject_policy_blocks_non_integral_floats():
    with pytest.raises(CanonicalizationError):
        canonical_json({"x": 1.5}, float_policy="reject")


def test_round_policy_accepts_realistic_floats_against_engine():
    # Floats that survive a real tool call are low-precision; these must verify.
    payload = {"temperature": 0.5, "ratio": 3.25, "limit": 100.0}
    message = action_message("req-1", ACTOR, CAPABILITY, "bash", payload)
    assert _engine_accepts(payload, message)


@pytest.mark.parametrize("places", [2, 6, 10, 13])
def test_both_policies_are_exact_at_reduced_precision(places):
    # The Python-vs-ryu disagreement needs ~17 significant digits to appear.
    for policy in ("allow", "round"):
        value = round(0.1234567890123456789, places)
        message = action_message(
            "req-1", ACTOR, CAPABILITY, "bash", {"x": value}, float_policy=policy
        )
        assert _engine_accepts({"x": value}, message), (policy, places)


def test_round_policy_signs_a_different_number_than_the_engine():
    # Guards the documented hazard: "round" rewrites the value to 15 significant
    # digits, so what gets signed is not the number the engine holds. This is
    # why "round" is the wrong default for full-precision payloads.
    value = 0.12345678901234568
    rounded = canonical_json({"x": value}, float_policy="round")
    allowed = canonical_json({"x": value}, float_policy="allow")
    assert rounded != allowed
    assert b'"x":0.123456789012346' in rounded
