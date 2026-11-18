"""Action receipts: the signed evidence the guardrail emits for every action.

A receipt binds, under a single ML-DSA-87 signature, the identity that acted,
the verification method that authorized it, the capability, the exact action
payload, and the delegation chain root. The signing payload is domain-separated
and length-prefixed so no field can be moved into another position without
breaking the signature -- the same construction the NTI reference verifier uses.

The signature is written in the NTI tagged form ``ml-dsa-87:{length}:{hex}``.
It is raw ML-DSA-87 bytes, never DER-encoded: ``-``, ``=``, whitespace and
base64 characters are rejected on read.
"""

from __future__ import annotations

import hashlib
import struct
from datetime import datetime, timezone
from typing import Any

from openhands_nti.canonical import canonical_json
from openhands_nti.delegation import DelegationProof
from openhands_nti.errors import NTIError

DOMAIN_SIGN = b"nti-openhands-action-v1:"
RECEIPT_VERSION = "nti-openhands-action/1.0"

# Order of the length-prefixed fields in the signed payload. Changing this list
# changes the signed bytes, so it is part of the wire contract.
SIGNED_FIELDS = (
    "receipt_id",
    "agent_did",
    "verification_method",
    "delegation_chain_root",
    "action_payload_sha256",
    "signed_at",
    "tool_name",
    "capability",
)


def _u32(value: int) -> bytes:
    return struct.pack(">I", value)


def _lp(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _u32(len(raw)) + raw


def signing_payload(fields: dict[str, str]) -> bytes:
    """Domain-separated, length-prefixed bytes the receipt signature covers."""
    payload = bytearray(DOMAIN_SIGN)
    for name in SIGNED_FIELDS:
        payload += _lp(fields[name])
    return bytes(payload)


def parse_tagged_signature(tag: str) -> bytes:
    """Parse ``ml-dsa-87:{length}:{hex}`` and return the raw signature bytes."""
    parts = tag.split(":")
    if len(parts) != 3:
        raise NTIError("signature tag must be ml-dsa-87:{length}:{hex}")
    algorithm, length, hexsig = parts
    if algorithm != "ml-dsa-87":
        raise NTIError(f"unexpected signature algorithm tag: {algorithm!r}")
    if any(c in hexsig for c in "-= \t\n"):
        raise NTIError("signature is not raw hex (looks DER/base64 encoded)")
    try:
        signature = bytes.fromhex(hexsig)
    except ValueError as exc:
        raise NTIError("signature is not valid hex") from exc
    if int(length) != len(signature):
        raise NTIError(f"tagged length {length} != actual {len(signature)} bytes")
    return signature


def format_tagged_signature(signature: bytes) -> str:
    return f"ml-dsa-87:{len(signature)}:{signature.hex()}"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_receipt(
    *,
    receipt_id: str,
    agent_did: str,
    verification_method: str,
    tool_name: str,
    capability: str,
    payload: Any,
    delegation_chain: list[dict[str, Any]],
    proof: DelegationProof,
    key_pair: Any,
    public_key_pem: str | None = None,
    signed_at: str | None = None,
) -> dict[str, Any]:
    """Assemble and sign a receipt. ``key_pair`` is a ``ube_foundation.PqcKeyPair``."""
    action_payload_sha256 = hashlib.sha256(canonical_json(payload)).hexdigest()
    signed_at = signed_at or _now()

    fields = {
        "receipt_id": receipt_id,
        "agent_did": agent_did,
        "verification_method": verification_method,
        "delegation_chain_root": proof.root_sha256.hex(),
        "action_payload_sha256": action_payload_sha256,
        "signed_at": signed_at,
        "tool_name": tool_name,
        "capability": capability,
    }
    signature = key_pair.sign_bytes(signing_payload(fields))

    public_key_bytes = bytes(key_pair.get_public_key_bytes())
    return {
        "receipt_version": RECEIPT_VERSION,
        "receipt_id": receipt_id,
        "agent_did": agent_did,
        "verification_method": verification_method,
        "algorithm": "ML-DSA-87",
        "signed_at": signed_at,
        "tool_name": tool_name,
        "capability": capability,
        "delegation_chain_root": proof.root_sha256.hex(),
        "action_payload_sha256": action_payload_sha256,
        "delegation_chain": delegation_chain,
        "merkle_proof": proof.to_json(),
        "ml_dsa_87_signature": format_tagged_signature(signature),
        "public_key": {
            "algorithm": "ML-DSA-87",
            "public_key_pem": public_key_pem,
            "fingerprint_sha256": hashlib.sha256(public_key_bytes).hexdigest(),
        },
        "signing": {
            "domain": DOMAIN_SIGN.decode(),
            "canonical_form": "b'nti-openhands-action-v1:' || uint32_be(len(s)) || s  for each signed field, in order",
            "signed_fields": list(SIGNED_FIELDS),
        },
    }


def verify_receipt(receipt: dict[str, Any], public_key: Any) -> bool:
    """Verify a receipt signature against a ``ube_foundation.PqcKeyPair`` public key."""
    try:
        fields = {name: receipt[name] for name in SIGNED_FIELDS}
    except KeyError:
        return False
    try:
        signature = parse_tagged_signature(receipt["ml_dsa_87_signature"])
    except (KeyError, NTIError):
        return False
    return bool(public_key.verify(signing_payload(fields), signature.hex()))
