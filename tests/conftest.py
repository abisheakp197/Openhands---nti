"""Shared fixtures: real ML-DSA-87 keys, a delegation chain, and a real tool.

These tests exercise the real ``ube_foundation`` bindings and the real
``openhands-sdk`` execution path -- no mocks.
"""

from __future__ import annotations

import pytest

pytest.importorskip("ube_foundation")
pytest.importorskip("openhands.sdk.tool.tool")

import ube_foundation as nti  # noqa: E402
from openhands.sdk.tool.tool import (  # noqa: E402
    Action,
    Observation,
    ToolAnnotations,
    ToolDefinition,
    ToolExecutor,
)
from pydantic import Field  # noqa: E402

AGENT_DID = "did:webvh:z6MkAgentSCID0000000000000000000000000000:agents.example.com"
ISSUER_DID = "did:webvh:z6MkIssuerSCID000000000000000000000000000:issuer.example.com"
CAPABILITY = "shell.execute"


class EchoAction(Action):
    command: str = Field(default="", description="command text")


class EchoObservation(Observation):
    pass


class EchoExecutor(ToolExecutor):
    def __call__(self, action, conversation=None):  # noqa: ARG002
        return EchoObservation.from_text(text=f"ran:{action.command}")


class BashTool(ToolDefinition[EchoAction, EchoObservation]):
    """A stand-in for a real tool (bash/file/browser) that runs an action."""

    @classmethod
    def create(cls, conv_state=None, **params):  # noqa: ARG003
        return [
            cls(
                description="echo a command",
                action_type=EchoAction,
                observation_type=EchoObservation,
                executor=EchoExecutor(),
                annotations=ToolAnnotations(readOnlyHint=True),
            )
        ]


@pytest.fixture
def key_pair():
    return nti.PqcKeyPair()


@pytest.fixture
def delegation_chain():
    return [
        {
            "delegation_id": "sha256:root",
            "parent_delegation_id": None,
            "issuer": ISSUER_DID,
            "subject": AGENT_DID,
            "scope": [CAPABILITY],
            "issued_at": "2026-01-01T00:00:00Z",
            "depth_remaining": 2,
        },
        {
            "delegation_id": "sha256:leaf",
            "parent_delegation_id": "sha256:root",
            "issuer": ISSUER_DID,
            "subject": AGENT_DID,
            "scope": [CAPABILITY, "file.write"],
            "issued_at": "2026-01-01T00:00:01Z",
            "depth_remaining": 1,
        },
    ]


@pytest.fixture
def tool():
    return BashTool.create()[0]
