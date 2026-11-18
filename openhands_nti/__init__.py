"""openhands-nti: drop-in Neutral Trust Infrastructure guardrail for OpenHands.

Wrap every OpenHands tool action in NTI verification -- ML-DSA-87 signatures and
Merkle delegation-chain proofs -- with a one-line change::

    from openhands_nti import NTIGuardrail

    guardrail = NTIGuardrail(
        agent_did="did:webvh:z6Mk...:agents.example.com",
        key_pair=key_pair,
        delegation_chain=chain,
    ).install()

    # ... run your agent as usual ...

    guardrail.uninstall()

Every bash command, Python execution, file edit, browser request, MCP call, and
client tool call is intercepted before it runs, signed, verified against the
delegation chain, and recorded. Denials fail closed: the tool never executes.
"""

from openhands_nti.audit import AuditTrail
from openhands_nti.canonical import action_message, canonical_json
from openhands_nti.delegation import (
    DelegationProof,
    build_proof,
    leaf_hash,
    merkle_root,
    node_hash,
    verify_proof,
)
from openhands_nti.errors import (
    CanonicalizationError,
    DelegationError,
    IdentityError,
    NTIBlocked,
    NTIError,
)
from openhands_nti.guardrail import NTIGuardrail, install_guardrail
from openhands_nti.policy import DEFAULT_TOOL_CAPABILITIES, capability_for
from openhands_nti.receipt import (
    RECEIPT_VERSION,
    build_receipt,
    format_tagged_signature,
    parse_tagged_signature,
    verify_receipt,
)

__version__ = "0.1.0"

__all__ = [
    "AuditTrail",
    "CanonicalizationError",
    "DEFAULT_TOOL_CAPABILITIES",
    "DelegationError",
    "DelegationProof",
    "IdentityError",
    "NTIBlocked",
    "NTIError",
    "NTIGuardrail",
    "RECEIPT_VERSION",
    "action_message",
    "build_proof",
    "build_receipt",
    "canonical_json",
    "capability_for",
    "format_tagged_signature",
    "install_guardrail",
    "leaf_hash",
    "merkle_root",
    "node_hash",
    "parse_tagged_signature",
    "verify_proof",
    "verify_receipt",
    "__version__",
]
