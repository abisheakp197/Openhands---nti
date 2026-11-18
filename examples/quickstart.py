"""End-to-end demonstration of the one-line NTI guardrail for OpenHands.

Run it::

    python examples/quickstart.py

It builds a real ML-DSA-87 key, a two-hop delegation chain, installs the
guardrail, runs an allowed action (receipt attached) and a denied action
(blocked, incident logged).
"""

from __future__ import annotations

import ube_foundation as nti

from openhands_nti import NTIGuardrail
from openhands_nti.errors import NTIBlocked

AGENT_DID = "did:webvh:z6MkAgentSCID0000000000000000000000000000:agents.example.com"
ISSUER_DID = "did:webvh:z6MkIssuerSCID000000000000000000000000000:issuer.example.com"


class _StubTool:
    def __init__(self, name: str):
        self.name = name


class _StubAction:
    def __init__(self, command: str):
        self._command = command

    def model_dump(self, mode: str = "python"):
        return {"command": self._command}


def main() -> None:
    key_pair = nti.PqcKeyPair()

    delegation_chain = [
        {
            "delegation_id": "sha256:root",
            "parent_delegation_id": None,
            "issuer": ISSUER_DID,
            "subject": AGENT_DID,
            "scope": ["shell.execute", "file.write"],
            "issued_at": "2026-01-01T00:00:00Z",
            "depth_remaining": 2,
        },
        {
            "delegation_id": "sha256:leaf",
            "parent_delegation_id": "sha256:root",
            "issuer": ISSUER_DID,
            "subject": AGENT_DID,
            "scope": ["shell.execute"],
            "issued_at": "2026-01-01T00:00:01Z",
            "depth_remaining": 1,
        },
    ]

    # The one-line change.
    guardrail = NTIGuardrail(
        agent_did=AGENT_DID,
        key_pair=key_pair,
        delegation_chain=delegation_chain,
    ).install()

    try:
        receipt = guardrail.authorize(_StubTool("bash"), _StubAction("ls -la"))
        print("Allowed action -> receipt", receipt["receipt_id"])
        print("  signature:", receipt["ml_dsa_87_signature"][:48], "...")

        # A capability that is not delegated is blocked, fail-closed.
        try:
            guardrail.authorize(_StubTool("browser"), _StubAction("https://example.com"))
        except NTIBlocked as exc:
            print("Blocked action ->", exc.reason)
    finally:
        guardrail.uninstall()


if __name__ == "__main__":
    main()
