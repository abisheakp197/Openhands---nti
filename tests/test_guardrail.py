"""End-to-end interception tests against the real OpenHands execution path."""

from __future__ import annotations

import asyncio
import json

import pytest
import ube_foundation as nti

from openhands_nti import NTIGuardrail, verify_receipt
from openhands_nti.errors import NTIBlocked, NTIError

from conftest import AGENT_DID, CAPABILITY, EchoAction, BashTool


@pytest.fixture
def guardrail(key_pair, delegation_chain):
    rail = NTIGuardrail(
        agent_did=AGENT_DID,
        key_pair=key_pair,
        delegation_chain=delegation_chain,
    )
    rail.install()
    try:
        yield rail
    finally:
        rail.uninstall()


def test_allowed_action_runs_and_gets_receipt(guardrail, tool):
    observation = tool(EchoAction(command="ls -la"))
    assert observation.content[0].text == "ran:ls -la"
    receipt = observation.nti_receipt
    assert receipt["agent_did"] == AGENT_DID
    assert receipt["capability"] == CAPABILITY
    assert receipt["ml_dsa_87_signature"].startswith("ml-dsa-87:")
    assert receipt["algorithm"] == "ML-DSA-87"


def test_receipt_signature_verifies(guardrail, tool, key_pair):
    observation = tool(EchoAction(command="whoami"))
    assert verify_receipt(observation.nti_receipt, key_pair)


def test_receipt_is_not_der_encoded(guardrail, tool):
    receipt = tool(EchoAction(command="id")).nti_receipt
    hexsig = receipt["ml_dsa_87_signature"].split(":")[2]
    assert all(c in "0123456789abcdef" for c in hexsig)
    assert "-" not in hexsig and "=" not in hexsig


def test_async_call_is_also_intercepted(guardrail, tool):
    observation = asyncio.run(tool.acall(EchoAction(command="uname -a")))
    assert observation.nti_receipt["capability"] == CAPABILITY


def test_uninstalled_guardrail_does_not_intercept(key_pair, delegation_chain, tool):
    observation = tool(EchoAction(command="ls"))
    assert not hasattr(observation, "nti_receipt")


def test_denied_capability_blocks_execution(key_pair, delegation_chain, tool):
    # Chain grants only file.write; shell.execute is not delegated.
    rail = NTIGuardrail(
        agent_did=AGENT_DID,
        key_pair=key_pair,
        delegation_chain=[{**delegation_chain[0], "scope": ["file.write"]}],
    )
    rail.install()
    try:
        with pytest.raises(NTIBlocked):
            tool(EchoAction(command="rm -rf /"))
        # Fail-closed: an incident was recorded.
        assert rail.audit.incidents()
    finally:
        rail.uninstall()


def test_unknown_capability_is_default_denied(key_pair, tool):
    # A chain that grants some other capability; the tool needs shell.execute.
    rail = NTIGuardrail(
        agent_did=AGENT_DID,
        key_pair=key_pair,
        delegation_chain=[{"delegation_id": "d", "subject": AGENT_DID, "scope": ["x"]}],
    )
    rail.install()
    try:
        with pytest.raises(NTIBlocked):
            tool(EchoAction(command="ls"))
    finally:
        rail.uninstall()


def test_forged_signature_is_rejected(key_pair, delegation_chain, tool):
    """A different key claiming the agent's DID must not authorize."""
    attacker = nti.PqcKeyPair()
    rail = NTIGuardrail(
        agent_did=AGENT_DID,
        key_pair=attacker,  # engine holds the real key for this DID
        delegation_chain=delegation_chain,
    )
    # Seed the engine with the *real* key so the attacker's signature is untrusted.
    engine = nti.TrustEngine()
    for record in delegation_chain:
        engine.grant(AGENT_DID, "shell.execute")
    engine.register_pqc_identity_key(AGENT_DID, key_pair.get_public_key_bytes())
    rail.engine = engine
    rail.install()
    try:
        with pytest.raises(NTIBlocked):
            tool(EchoAction(command="ls"))
    finally:
        rail.uninstall()


def test_engine_denial_is_fail_closed(key_pair, delegation_chain, tool):
    """Tampering with the engine state after install must block, not allow."""
    rail = NTIGuardrail(
        agent_did=AGENT_DID,
        key_pair=key_pair,
        delegation_chain=delegation_chain,
    )
    rail.install()
    try:
        # Revoke nothing, but swap in an engine that grants nothing.
        rail.engine = nti.TrustEngine()
        with pytest.raises(NTIBlocked):
            tool(EchoAction(command="ls"))
    finally:
        rail.uninstall()


def test_double_install_is_idempotent(guardrail):
    assert guardrail.install() is guardrail


def test_conflicting_guardrail_cannot_install(guardrail, key_pair, delegation_chain):
    other = NTIGuardrail(
        agent_did=AGENT_DID, key_pair=key_pair, delegation_chain=delegation_chain
    )
    with pytest.raises(NTIError):
        other.install()


def test_audit_records_allowed_actions(guardrail, tool):
    tool(EchoAction(command="ls"))
    allows = [r for r in guardrail.audit.records if r["decision"] == "allow"]
    assert allows and allows[0]["capability"] == CAPABILITY


def test_on_block_callback_receives_incident(key_pair, delegation_chain, tool):
    seen = []
    rail = NTIGuardrail(
        agent_did=AGENT_DID,
        key_pair=key_pair,
        delegation_chain=[{**delegation_chain[0], "scope": ["file.write"]}],
        on_block=seen.append,
    )
    rail.install()
    try:
        with pytest.raises(NTIBlocked):
            tool(EchoAction(command="ls"))
        assert seen and seen[0]["decision"] == "deny"
    finally:
        rail.uninstall()


def test_context_manager_installs_and_restores(key_pair, delegation_chain, tool):
    with NTIGuardrail(
        agent_did=AGENT_DID, key_pair=key_pair, delegation_chain=delegation_chain
    ):
        assert hasattr(tool(EchoAction(command="ls")), "nti_receipt")
    assert not hasattr(tool(EchoAction(command="ls")), "nti_receipt")


def test_capability_overrides(key_pair, delegation_chain, tool):
    rail = NTIGuardrail(
        agent_did=AGENT_DID,
        key_pair=key_pair,
        delegation_chain=[{**delegation_chain[0], "scope": ["custom.cap"]}],
        capability_overrides={"bash": "custom.cap"},
    )
    rail.install()
    try:
        observation = tool(EchoAction(command="ls"))
        assert observation.nti_receipt["capability"] == "custom.cap"
    finally:
        rail.uninstall()


def test_receipt_binds_action_payload(guardrail, tool):
    observation = tool(EchoAction(command="cat /etc/hosts"))
    receipt = observation.nti_receipt
    # The digest must match the canonical payload the tool actually received.
    from openhands_nti.canonical import canonical_json
    import hashlib

    payload = EchoAction(command="cat /etc/hosts").model_dump(mode="json")
    assert receipt["action_payload_sha256"] == hashlib.sha256(
        canonical_json(payload)
    ).hexdigest()
