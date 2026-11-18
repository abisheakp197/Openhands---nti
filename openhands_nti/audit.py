"""Append-only incident and receipt audit trail.

Every decision -- allow or deny -- is recorded. Denials are recorded *before*
the block is raised so an incident survives even if the caller swallows the
exception. Records are JSON lines, one object per line.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("openhands_nti")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AuditTrail:
    """Thread-safe JSONL audit trail, optionally mirrored to a file."""

    def __init__(self, path: str | os.PathLike[str] | None = None):
        self._path = Path(path) if path else None
        self._lock = threading.Lock()
        self._records: list[dict[str, Any]] = []
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: dict[str, Any]) -> None:
        entry = {"logged_at": _now(), **event}
        with self._lock:
            self._records.append(entry)
            if self._path is not None:
                with self._path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(entry, sort_keys=True) + "\n")
        level = logging.ERROR if event.get("decision") == "deny" else logging.INFO
        logger.log(level, "openhands-nti %s", json.dumps(entry, sort_keys=True))

    @property
    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._records)

    def incidents(self) -> list[dict[str, Any]]:
        return [r for r in self.records if r.get("decision") == "deny"]
