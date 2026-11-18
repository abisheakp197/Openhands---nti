# Architecture

`openhands-nti` is the NTI wrapper for the OpenHands agent framework. It sits
between the agent loop and tool execution, and routes every action through the
NTI Rust sidecar for post-quantum signing and verification before the action is
allowed to run.

## Action flow

```mermaid
flowchart TD
    Agent["OpenHands Agent<br/>LLM reasoning loop"]
    Wrapper["NTI Wrapper<br/>openhands_nti.guardrail<br/>intercepts ToolDefinition.__call__"]
    Canon["Canonicalizer<br/>canonical.py<br/>float_policy=round"]
    Chain["Merkle Delegation Chain<br/>delegation.py (RFC 6962)"]
    Sidecar["Rust Sidecar<br/>ube-foundation TrustEngine"]
    Sign["ML-DSA-87 Signature<br/>ml-dsa-87:4627:hex"]
    Verify["Verification Endpoint<br/>TrustEngine.evaluate()"]
    Exec["Execute tool<br/>attach signed receipt"]
    Block["Block action<br/>fail-closed + incident"]

    Agent -->|"tool call (bash, python, file, web, MCP)"| Wrapper
    Wrapper --> Canon
    Wrapper --> Chain
    Canon -->|"canonical action bytes"| Sidecar
    Chain -->|"inclusion proof -> chain root"| Sidecar
    Sidecar --> Sign
    Sign -->|"signed request"| Verify
    Verify -->|"Allow"| Exec
    Verify -->|"Deny / any error"| Block
    Exec -->|"observation.nti_receipt"| Agent
    Block -->|"NTIBlocked"| Agent
```

## The five stages

| # | Stage | Component | What it does |
| --- | --- | --- | --- |
| 1 | **OpenHands Agent** | `openhands.sdk` | The LLM loop decides on an action and calls a tool. |
| 2 | **NTI Wrapper** | `openhands_nti.guardrail` | Intercepts `ToolDefinition.__call__`, the single method every tool call funnels through. Resolves the action's NTI capability. |
| 3 | **Rust Sidecar** | `ube-foundation` (`TrustEngine`) | Receives the canonicalized action and the delegation proof. Holds the agent's registered ML-DSA-87 public key. |
| 4 | **ML-DSA-87 Signature** | `PqcKeyPair.sign_bytes` | Signs the action over `(id, actor, capability, action, input)`. Emitted as `ml-dsa-87:{length}:{hex}` — raw bytes, never DER/ECDSA. |
| 5 | **Verification Endpoint** | `TrustEngine.evaluate()` | Returns `Allow` or `Deny`. Only `Allow` lets the tool run; anything else blocks, fail-closed. |

## Sequence

```mermaid
sequenceDiagram
    participant A as OpenHands Agent
    participant W as NTI Wrapper
    participant C as Canonicalizer
    participant D as Delegation Chain
    participant S as Rust Sidecar
    participant V as Verification Endpoint

    A->>W: tool call (action payload)
    W->>W: resolve capability (e.g. shell.execute)
    W->>D: build Merkle inclusion proof
    D-->>W: proof folds to chain root
    W->>C: canonicalize (float_policy=round)
    C-->>W: canonical action bytes
    W->>S: sign_bytes(message)
    S-->>W: ML-DSA-87 signature (4627 bytes)
    W->>V: evaluate(signed request + proof)
    alt Allow
        V-->>W: decision = Allow
        W->>A: run tool, attach observation.nti_receipt
    else Deny or error
        V-->>W: decision = Deny
        W->>A: raise NTIBlocked (tool never runs)
    end
```

## Fail-closed guarantee

Every failure path blocks execution: an undelegated capability, a delegation
proof that does not fold to the chain root, a non-`Allow` verdict, a payload
that cannot be canonicalized, or any unexpected internal error. The tool never
executes, and the incident is recorded before the exception is raised.

See [SECURITY.md](SECURITY.md) for the threat model and the float-canonicalization
hazard.

## Interactive diagram (gitdiagram)

Generate a live, navigable architecture map from this repository with
[gitdiagram.com](https://gitdiagram.com):

[![gitdiagram](https://img.shields.io/badge/Architecture-gitdiagram.com-blue)](https://gitdiagram.com/abisheakp197/Openhands---nti)

Direct link: <https://gitdiagram.com/abisheakp197/Openhands---nti>

> If the diagram does not render yet, it is because gitdiagram indexes public
> repositories on demand — open the link once and it will generate from the
> current `main` branch.
