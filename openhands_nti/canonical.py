"""Canonical JSON that byte-matches the NTI engine's ``serde_json`` encoder.

The NTI ``TrustEngine`` re-serializes the parsed ``input`` value with
``serde_json`` and verifies the ML-DSA-87 signature over the tuple::

    (id, actor, capability, action, input)

The exact bytes matter: one byte of difference and verification fails closed.
This module reproduces the engine's encoder for the JSON types Python and Rust
represent identically, and refuses (fails closed) where the two provably differ.

What matches exactly
--------------------
* Objects: keys sorted by Unicode code point, compact (no whitespace).
* Strings: raw UTF-8, ``"`` and ``\\`` escaped, control characters below
  U+0020 escaped (``\\b``/``\\t``/``\\n``/``\\f``/``\\r`` short forms, the rest as
  ``\\u00XX``). ``/`` is not escaped. This is what ``json.dumps(..., ensure_ascii=False)``
  emits, and it matches ``serde_json``.
* Integers: decimal. Rust keeps full ``i64``/``u64`` precision, so any Python
  integer outside ``[-2**63, 2**64 - 1]`` cannot round-trip and is rejected.
* Booleans and ``null``.

Floats
------
Cross-language float canonicalization is the one place where Python and Rust
disagree. ``serde_json`` parses and re-serializes ``f64`` values with its own
shortest-form algorithm, and for a non-trivial fraction of full-precision
doubles the bytes it produces differ from Python's ``repr``. A signature
computed over Python's bytes then fails to verify against the engine, which is
a *fail-closed* outcome: the action is blocked, never allowed. See
``float_policy`` below and ``SECURITY.md``.
"""

from __future__ import annotations

import json
import math
from typing import Any

from openhands_nti.errors import CanonicalizationError

# Integers outside this range are represented as ``f64`` by ``serde_json`` and
# therefore do not round-trip through the engine's canonical form.
_I64_MIN = -(2**63)
_U64_MAX = 2**64 - 1

_FLOAT_POLICIES = ("round", "reject", "allow")


def _encode_string(value: str) -> str:
    # json.dumps with ensure_ascii=False matches serde_json escaping for the
    # BMP and for astral characters: raw UTF-8, only the mandated escapes.
    return json.dumps(value, ensure_ascii=False)


def _shortest_parts(value: float) -> tuple[bool, str, int]:
    """Return ``(negative, digits, exponent)`` for ``value`` in scientific form.

    ``digits`` holds the shortest round-tripping significant digits and
    ``exponent`` is the base-10 exponent of the first digit (``d.ddd * 10**exponent``).
    """
    text = repr(value)
    negative = text.startswith("-")
    if negative:
        text = text[1:]
    if "e" in text:
        mantissa, _, exp_text = text.partition("e")
        exp = int(exp_text)
    else:
        mantissa, exp = text, 0
    if "." in mantissa:
        int_part, frac_part = mantissa.split(".")
    else:
        int_part, frac_part = mantissa, ""
    combined = int_part + frac_part
    stripped = combined.lstrip("0")
    if stripped == "":
        return negative, "0", 0
    leading = len(combined) - len(stripped)
    exponent = len(combined) - 1 - leading + exp - len(frac_part)
    digits = stripped.rstrip("0") or "0"
    return negative, digits, exponent


def _encode_float(value: float, policy: str, digits: int) -> str:
    if not math.isfinite(value):
        raise CanonicalizationError(
            f"non-finite float {value!r} cannot be canonicalized for signing"
        )
    if value == 0.0:
        return "-0.0" if math.copysign(1.0, value) < 0 else "0.0"

    if policy == "reject" and not float(value).is_integer():
        raise CanonicalizationError(
            f"non-integral float {value!r} rejected by float_policy='reject'; "
            "encode it as a string or an integer"
        )
    if policy == "round":
        value = float(f"{value:.{digits}g}")

    negative, digits_str, exponent = _shortest_parts(value)
    sign = "-" if negative else ""
    count = len(digits_str)

    # serde_json (ryu) prints plain decimal for exponents in [-5, 16) and
    # scientific notation otherwise.
    if -5 <= exponent < 16:
        if exponent >= 0:
            if count <= exponent + 1:
                body = digits_str + "0" * (exponent + 1 - count) + ".0"
            else:
                body = digits_str[: exponent + 1] + "." + digits_str[exponent + 1 :]
        else:
            body = "0." + "0" * (-exponent - 1) + digits_str
        return sign + body

    mantissa = digits_str[0] + ("." + digits_str[1:] if count > 1 else "")
    exp_sign = "+" if exponent >= 0 else "-"
    return f"{sign}{mantissa}e{exp_sign}{abs(exponent)}"


def _encode(value: Any, out: list[str], policy: str, digits: int) -> None:
    if value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif value is None:
        out.append("null")
    elif isinstance(value, str):
        out.append(_encode_string(value))
    elif isinstance(value, int):
        if not (_I64_MIN <= value <= _U64_MAX):
            raise CanonicalizationError(
                f"integer {value} is outside the range serde_json round-trips "
                "as an integer; encode it as a string"
            )
        out.append(str(value))
    elif isinstance(value, float):
        out.append(_encode_float(value, policy, digits))
    elif isinstance(value, dict):
        out.append("{")
        first = True
        for key in sorted(value):
            if not isinstance(key, str):
                raise CanonicalizationError(
                    f"JSON object keys must be strings, got {type(key).__name__}"
                )
            if not first:
                out.append(",")
            first = False
            out.append(_encode_string(key))
            out.append(":")
            _encode(value[key], out, policy, digits)
        out.append("}")
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _encode(item, out, policy, digits)
        out.append("]")
    else:
        raise CanonicalizationError(
            f"type {type(value).__name__} is not JSON-serializable for signing"
        )


def canonical_json(
    value: Any, *, float_policy: str = "round", float_digits: int = 15
) -> bytes:
    """Encode ``value`` to the canonical bytes the NTI engine signs over.

    Args:
        value: A JSON-compatible object.
        float_policy: ``"round"`` (default) rounds non-integral floats to
            ``float_digits`` significant digits before encoding; ``"reject"``
            fails closed on any non-integral float; ``"allow"`` encodes the
            float as-is.
        float_digits: Significant digits used when ``float_policy == "round"``.

    Raises:
        CanonicalizationError: If ``value`` contains a type that cannot be
            represented identically in Python and Rust.
    """
    if float_policy not in _FLOAT_POLICIES:
        raise CanonicalizationError(
            f"unknown float_policy {float_policy!r}; expected one of {_FLOAT_POLICIES}"
        )
    out: list[str] = []
    _encode(value, out, float_policy, float_digits)
    return "".join(out).encode("utf-8")


def action_message(
    request_id: str,
    actor: str,
    capability: str,
    action: str,
    payload: Any,
    *,
    float_policy: str = "round",
    float_digits: int = 15,
) -> bytes:
    """The exact bytes the engine signs: the canonical 5-tuple."""
    return canonical_json(
        [request_id, actor, capability, action, payload],
        float_policy=float_policy,
        float_digits=float_digits,
    )
