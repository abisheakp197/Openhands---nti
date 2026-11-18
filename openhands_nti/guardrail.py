"""The NTI guardrail: intercept every OpenHands tool execution.

Interception point
------------------
Every tool call in the OpenHands SDK funnels through
:meth:`openhands.sdk.tool.tool.ToolDefinition.__call__` -- the sync path from the
agent loop and the async ``acall`` path (which dispatches back through
``__call__``) both pass here. Patching that single method covers bash, the Python
IPython tool, the file editor, browser/web tools, MCP tools, and client tools
alike, without touching any individual tool.

Per action, in order (all fail-closed):

1. Resolve the capability the tool requires.
2. Prove a delegation record granting that capability to the agent's DID is
   included in the Merkle delegation chain.
3. Canonicalize the action and sign it with ML-DSA-87.
4. Ask the NTI engine for a verdict (capability granted, key trusted, signature
   valid). Anything other than ``Allow`` blocks the action.
5. Only then run the original tool and attach the signed receipt to its output.
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from collections.abc import Callable
from typing import Any

from openhands_nti.audit import AuditTrail
from openhands_nti.canonical import action_message
from openhands_nti.delegation import DelegationProof, build_proof, verify_proof
from openhands_nti.errors import (
    CanonicalizationError,
    DelegationError,
    IdentityError,
    NTIBlocked,
    NTIError,
)
from openhands_nti.policy import capability_for
from openhands_nti.receipt import build_receipt

logger = logging.getLogger("openhands_nti")

_INSTALL_LOCK = threading.Lock()
_ACTIVE: "NTIGuardrail | None" = None


def _load_openhands() -> Any:
    try:
        from openhands.sdk.tool.tool import ToolDefinition
    except ImportError as exc:  # pragma: no cover - exercised via dependency checks
        raise NTIError(
            "openhands-sdk is required to install the guardrail; "
            "install openhands-nti[openhands] or `pip install openhands-sdk`"
        ) from exc
    return ToolDefinition


def _load_nti() -> Any:
    try:
        import ube_foundation
    except ImportError as exc:  # pragma: no cover - exercised via dependency checks
        raise NTIError(
            "ube-foundation is required for ML-DSA-87 signing and policy "
            "evaluation; install `ube-foundation`"
        ) from exc
    return ube_foundation


class NTIGuardrail:
    """Authorize and sign every OpenHands tool action.

    Args:
        agent_did: The DID of the acting agent (the delegation ``subject``).
        key_pair: An ML-DSA-87 key pair (``ube_foundation.PqcKeyPair``).
        delegation_chain: Ordered delegation records. Each record must carry
            ``subject`` and ``scope`` (a capability string or list).
        verification_method: DID URL of the ML-DSA-87 verification method that
            authorizes ``agent_did``. Defaults to ``{agent_did}#ml-dsa-87``.
        engine: Optional preconfigured ``ube_foundation.TrustEngine``. A fresh one
            is created and seeded from the delegation chain if omitted.
        capability_overrides: Extra tool-name -> capability mappings.
        capability_resolver: Fully custom tool-name -> capability function.
        float_policy / float_digits: See :func:`openhands_nti.canonical.canonical_json`.
        audit_path: Optional JSONL path for the audit trail.
        on_block: Optional callback invoked with the incident dict before raising.
    """

    def __init__(
        self,
        *,
        agent_did: str,
        key_pair: Any,
        delegation_chain: list[dict[str, Any]],
        verification_method: str | None = None,
        engine: Any | None = None,
        capability_overrides: dict[str, str] | None = None,
        capability_resolver: Callable[[str], str] | None = None,
        float_policy: str = "round",
        float_digits: int = 15,
        audit_path: str | None = None,
        on_block: Callable[[dict[str, Any]], None] | None = None,
    ):
        if not agent_did:
            raise IdentityError("agent_did is required")
        if key_pair is None:
            raise IdentityError("key_pair is required")
        if not delegation_chain:
            raise DelegationError("delegation_chain must contain at least one record")

        self.agent_did = agent_did
        self.key_pair = key_pair
        self.delegation_chain = list(delegation_chain)
        self.verification_method = verification_method or f"{agent_did}#ml-dsa-87"
        self.capability_overrides = dict(capability_overrides or {})
        self.capability_resolver = capability_resolver
        self.float_policy = float_policy
        self.float_digits = float_digits
        self.audit = AuditTrail(audit_path)
        self.on_block = on_block

        if engine is None:
            nti = _load_nti()
            engine = nti.TrustEngine()
            self._seed_engine(engine)
        self.engine = engine

        self._original_call: Callable[..., Any] | None = None
        self._installed = False

    # -- engine seeding ---------------------------------------------------
    def _seed_engine(self, engine: Any) -> None:
        """Grant delegated capabilities and register the ML-DSA-87 identity key."""
        for record in self.delegation_chain:
            if record.get("subject") != self.agent_did:
                continue
            scope = record.get("scope")
            capabilities = [scope] if isinstance(scope, str) else list(scope or [])
            for capability in capabilities:
                engine.grant(self.agent_did, capability)
        engine.register_pqc_identity_key(
            self.agent_did, self.key_pair.get_public_key_bytes()
        )

    # -- installation -----------------------------------------------------
    def install(self) -> "NTIGuardrail":
        """Patch ``ToolDefinition.__call__`` process-wide. Idempotent."""
        global _ACTIVE
        tool_definition = _load_openhands()
        with _INSTALL_LOCK:
            if _ACTIVE is not None and _ACTIVE is not self:
                raise NTIError(
                    "another NTIGuardrail is already installed; call "
                    "uninstall() before installing a different one"
                )
            if self._installed:
                return self
            self._original_call = tool_definition.__call__
            guardrail = self
            original = self._original_call

            def guarded_call(inner_self: Any, action: Any, conversation: Any = None) -> Any:
                receipt = guardrail.authorize(inner_self, action)
                observation = original(inner_self, action, conversation)
                try:
                    object.__setattr__(observation, "nti_receipt", receipt)
                except Exception:  # pragma: no cover - observation is always a pydantic model
                    logger.warning("could not attach receipt to observation")
                return observation

            guarded_call.__wrapped__ = original  # type: ignore[attr-defined]
            tool_definition.__call__ = guarded_call
            self._installed = True
            _ACTIVE = self
        logger.info("openhands-nti guardrail installed for %s", self.agent_did)
        return self

    def uninstall(self) -> None:
        """Restore the original ``ToolDefinition.__call__``."""
        global _ACTIVE
        tool_definition = _load_openhands()
        with _INSTALL_LOCK:
            if not self._installed:
                return
            tool_definition.__call__ = self._original_call
            self._installed = False
            if _ACTIVE is self:
                _ACTIVE = None
        logger.info("openhands-nti guardrail uninstalled")

    def __enter__(self) -> "NTIGuardrail":
        return self.install()

    def __exit__(self, *exc_info: Any) -> None:
        self.uninstall()

    # -- core -------------------------------------------------------------
    def _payload(self, action: Any) -> dict[str, Any]:
        if hasattr(action, "model_dump"):
            return action.model_dump(mode="json")
        raise CanonicalizationError(
            f"action of type {type(action).__name__} is not a pydantic model"
        )

    def authorize(self, tool: Any, action: Any) -> dict[str, Any]:
        """Authorize one action and return its signed receipt, or raise.

        Raises:
            NTIBlocked: The action is denied or cannot be proven authorized.
        """
        tool_name = getattr(tool, "name", type(tool).__name__)
        capability = capability_for(
            tool_name, self.capability_overrides, self.capability_resolver
        )
        try:
            payload = self._payload(action)
            request_id = f"req-{uuid.uuid4().hex}"
            proof = self._delegation_proof(capability)
            message = action_message(
                request_id,
                self.agent_did,
                capability,
                tool_name,
                payload,
                float_policy=self.float_policy,
                float_digits=self.float_digits,
            )
            signature = self.key_pair.sign_bytes(message)
            self._evaluate(request_id, capability, tool_name, payload, signature)
            receipt = self._receipt(capability, tool_name, payload, proof)
        except NTIBlocked:
            raise
        except NTIError as exc:
            raise self._block(
                tool_name, capability, reason="error", detail=str(exc)
            ) from exc
        except Exception as exc:  # fail closed on anything unexpected
            raise self._block(
                tool_name,
                capability,
                reason="internal-error",
                detail=f"{type(exc).__name__}: {exc}",
            ) from exc

        self.audit.record(
            {
                "decision": "allow",
                "tool": tool_name,
                "capability": capability,
                "agent_did": self.agent_did,
                "receipt_id": receipt["receipt_id"],
                "action_payload_sha256": receipt["action_payload_sha256"],
            }
        )
        return receipt

    def _delegation_proof(self, capability: str) -> DelegationProof:
        proof = build_proof(
            self.delegation_chain, subject=self.agent_did, capability=capability
        )
        if not verify_proof(self.delegation_chain, proof):
            raise DelegationError("delegation proof failed to fold to the chain root")
        return proof

    def _evaluate(
        self,
        request_id: str,
        capability: str,
        tool_name: str,
        payload: dict[str, Any],
        signature: bytes,
    ) -> None:
        request = {
            "id": request_id,
            "actor": self.agent_did,
            "capability": capability,
            "action": tool_name,
            "input": payload,
            "signature": None,
            "pqc_signature": {
                "algorithm": "ML-DSA-87",
                "signature": list(signature),
            },
            "public_key": None,
            "pqc_public_key": list(self.key_pair.get_public_key_bytes()),
            "token": None,
            "identity_claim": None,
        }
        verdict = json.loads(self.engine.evaluate(json.dumps(request)))
        if verdict.get("decision") != "Allow":
            raise NTIBlocked(
                f"NTI engine denied {tool_name!r}: {verdict.get('reason', 'denied')}",
                reason=verdict.get("reason", "denied"),
            )

    def _receipt(
        self,
        capability: str,
        tool_name: str,
        payload: dict[str, Any],
        proof: DelegationProof,
    ) -> dict[str, Any]:
        return build_receipt(
            receipt_id=f"rcpt-{uuid.uuid4().hex}",
            agent_did=self.agent_did,
            verification_method=self.verification_method,
            tool_name=tool_name,
            capability=capability,
            payload=payload,
            delegation_chain=self.delegation_chain,
            proof=proof,
            key_pair=self.key_pair,
        )

    def _block(self, tool_name: str, capability: str, *, reason: str, detail: str) -> NTIBlocked:
        incident = {
            "decision": "deny",
            "reason": reason,
            "tool": tool_name,
            "capability": capability,
            "agent_did": self.agent_did,
            "detail": detail,
        }
        self.audit.record(incident)
        if self.on_block is not None:
            try:
                self.on_block(incident)
            except Exception:  # pragma: no cover - callback must not mask the block
                logger.exception("on_block callback failed")
        logger.error("openhands-nti blocked %s: %s", tool_name, detail)
        return NTIBlocked(
            f"openhands-nti blocked {tool_name!r} ({capability}): {detail}",
            reason=reason,
        )


def install_guardrail(**kwargs: Any) -> NTIGuardrail:
    """One-call install: build an :class:`NTIGuardrail` and patch OpenHands."""
    return NTIGuardrail(**kwargs).install()
