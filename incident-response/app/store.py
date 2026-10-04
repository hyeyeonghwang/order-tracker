"""Filesystem persistence for incident records."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any


class IncidentStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._latest_id: str | None = self._discover_latest()

    def _path(self, incident_id: str) -> Path:
        return self.root / f"{incident_id}.json"

    def _discover_latest(self) -> str | None:
        files = sorted(self.root.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        return files[0].stem if files else None

    def save(self, record: dict[str, Any]) -> None:
        with self._lock:
            path = self._path(record["id"])
            path.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
            self._latest_id = record["id"]

    def update(self, incident_id: str, **fields: Any) -> dict[str, Any] | None:
        with self._lock:
            path = self._path(incident_id)
            if not path.exists():
                return None
            data = json.loads(path.read_text(encoding="utf-8"))
            data.update(fields)
            path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
            self._latest_id = incident_id
            return data

    def get(self, incident_id: str) -> dict[str, Any] | None:
        path = self._path(incident_id)
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def latest(self) -> dict[str, Any] | None:
        with self._lock:
            if not self._latest_id:
                self._latest_id = self._discover_latest()
            if not self._latest_id:
                return None
            return self.get(self._latest_id)

    def list_summaries(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for path in sorted(self.root.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            items.append(
                {
                    "id": data.get("id"),
                    "status": data.get("status"),
                    "alert_name": data.get("alert_name"),
                    "created_at": data.get("created_at"),
                    "updated_at": data.get("updated_at"),
                    "fingerprint": data.get("fingerprint"),
                }
            )
        return items
