# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately to **abisheakp197@gmail.com**.
Please do not open a public issue for anything exploitable. We aim to
acknowledge reports within 72 hours.

Include a description, a minimal reproduction, the affected version, and any
suggested fix.

## Threat model

`openhands-nti` sits between the OpenHands agent loop and tool execution. It
answers one question, fail-closed: **is this action authorized for this agent,
and can we prove it cryptographically?**

The guardrail assumes:

* The agent's private ML-DSA-87 key is held by the runtime and never exposed to
  the model.
* The delegation chain is issued by a trusted authority out of band.
* The NTI `TrustEngine` and `ube_foundation` bindings are trusted code.

It defends against:

* An agent (or a prompt-injected model) attempting an action outside its
  delegated capability. The action is blocked before execution.
* A forged or substituted signature. The engine holds the agent's registered
  public key, so a signature from any other key is denied.
* A tampered delegation chain. The Merkle proof is folded back to the recomputed
  chain root; any change breaks the proof.
* Payload tampering between signing and execution. The receipt binds the exact
  canonical payload digest.

It does **not** defend against a compromised host, a malicious `ube_foundation`
build, or key exfiltration.

## Fail-closed guarantee

Every failure path raises `NTIBlocked` and prevents execution:

| Failure | Result |
| --- | --- |
| Capability not delegated to the agent | blocked |
| Delegation proof does not fold to the chain root | blocked |
| Engine verdict is anything but `Allow` | blocked |
| Payload cannot be canonicalized | blocked |
| Unexpected internal error | blocked |

Denials are written to the audit trail **before** the exception is raised, so an
incident survives even if the caller swallows the exception.

## Interception point and its assumptions

The guardrail patches `openhands.sdk.tool.tool.ToolDefinition.__call__`. This is
the single method every tool call funnels through: the sync path calls it
directly, and the async `acall` path dispatches back through it. Patching it
covers built-in, MCP, and client tools uniformly.

Two assumptions follow from this choice, and both are fail-closed if violated:

1. **Tool executions go through `ToolDefinition.__call__`.** If a future
   OpenHands release adds an execution path that bypasses it, that path would
   not be intercepted. This is a coverage gap, not an authorization bypass: the
   guardrail never *allows* an unauthorized action, it can only fail to observe
   one. Pin `openhands-sdk` and re-run the test suite when upgrading.
2. **Observations are pydantic models.** The receipt is attached with
   `object.__setattr__`, which works on the frozen observation models OpenHands
   returns. If attachment fails, a warning is logged and the observation is
   returned unmodified; the action was already authorized and signed.

## Canonicalization: the float hazard

The NTI engine signs over the tuple `(id, actor, capability, action, input)`,
re-serialized with Rust's `serde_json`. For a signature computed in Python to
verify, the bytes must match exactly.

For strings, integers, booleans, `null`, and objects, Python and `serde_json`
agree byte-for-byte. **Floats are the exception.** `serde_json` parses and
re-serializes `f64` values with its own algorithm, and for a non-trivial fraction
of doubles -- especially full-precision values with many significant digits --
the bytes differ from Python's `repr`. A signature over the Python bytes then
fails to verify against the engine.

This is a *fail-closed* outcome: the action is blocked, never allowed. It is an
availability concern, not an authorization bypass. Even so, it is worth handling
deliberately, because a false denial is a denial of service on the agent.

`canonical_json` exposes a `float_policy`:

* `"round"` (default) rounds non-integral floats to `float_digits` (default 15)
  significant digits before encoding. Realistic tool inputs -- measurements,
  ratios, coordinates with a handful of decimal places -- verify exactly. This
  is the recommended setting. Note it is a default, not an enforcement: it can
  be overridden per call and on `NTIGuardrail(...)`, so a caller passing `"allow"`
  gets unrounded bytes. Rounding also signs over the rounded value, so
  `0.12345678901234568` is signed as `0.123456789012346`.
* `"reject"` fails closed on any non-integral float. Use it when a false denial
  is preferable to a false allow, and encode floats as strings or integers.
* `"allow"` encodes floats as-is. Use only when you have verified parity for your
  exact value domain.

Integers outside `[-2**63, 2**64 - 1]` and non-finite floats (`inf`, `nan`) are
always rejected: they cannot round-trip through the engine's canonical form.

If you sign high-precision floats, test them against your pinned engine version
before deploying. `tests/test_canonical.py` shows how.

## Cryptography

* **Signatures:** ML-DSA-87 (FIPS 204), via `ube_foundation`. Keys are 2592-byte
  public / 4896-byte private. Signatures are 4627 bytes.
* **Receipt signing payload:** domain-separated (`nti-openhands-action-v1:`) and
  length-prefixed, so no field can be shifted into another position without
  breaking the signature.
* **Merkle tree:** SHA-256, RFC 6962 construction with the NTI domain separators
  `nti-delegation-leaf-v1:` and `nti-delegation-node-v1:`.
