"""Incident response HTTP service — Grafana webhook → coding assistant."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .agent_runner import run_coding_assistant
from .context import build_incident_context
from .store import IncidentStore

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("incident-response")

DATA_DIR = Path(os.getenv("INCIDENT_DATA_DIR", "/data/incidents"))
WORKSPACE = Path(os.getenv("WORKSPACE_PATH", "/workspace"))
DEDUPE_SECONDS = int(os.getenv("ALERT_DEDUPE_SECONDS", "300"))
AGENT_TIMEOUT = int(os.getenv("AGENT_TIMEOUT_SECONDS", "600"))

store = IncidentStore(DATA_DIR)
_dedupe_lock = threading.Lock()
_recent_fingerprints: dict[str, float] = {}

app = FastAPI(title="Incident Response", version="0.1.0")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fingerprint(alert: dict[str, Any]) -> str:
    labels = alert.get("labels") or {}
    if isinstance(labels, dict) and alert.get("fingerprint"):
        return str(alert["fingerprint"])
    key = {
        "alertname": labels.get("alertname") if isinstance(labels, dict) else None,
        "labels": labels,
        "annotations": alert.get("annotations") or {},
        "status": alert.get("status"),
    }
    blob = json.dumps(key, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _is_duplicate(fp: str) -> bool:
    now = time.time()
    with _dedupe_lock:
        expired = [k for k, t in _recent_fingerprints.items() if now - t > DEDUPE_SECONDS]
        for k in expired:
            _recent_fingerprints.pop(k, None)
        if fp in _recent_fingerprints:
            return True
        _recent_fingerprints[fp] = now
        return False


def _process_firing_alert(incident_id: str, alert: dict[str, Any], raw_payload: Any) -> None:
    """Background worker: gather context, invoke agent, persist result."""
    try:
        store.update(
            incident_id,
            status="collecting_context",
            updated_at=_utcnow(),
        )
        context = build_incident_context(
            alert=alert,
            raw_payload=raw_payload,
            workspace=WORKSPACE,
        )
        store.update(
            incident_id,
            status="invoking_assistant",
            context=context,
            updated_at=_utcnow(),
        )
        result = run_coding_assistant(
            incident_id=incident_id,
            context=context,
            workspace=WORKSPACE,
            timeout_seconds=AGENT_TIMEOUT,
        )
        store.update(
            incident_id,
            status="completed" if result.get("ok") else "assistant_failed",
            assistant=result,
            updated_at=_utcnow(),
            completed_at=_utcnow(),
        )
        logger.info("Incident %s finished with status=%s", incident_id, store.get(incident_id).get("status"))
    except Exception as exc:  # noqa: BLE001 — record any failure clearly
        logger.exception("Incident %s failed", incident_id)
        store.update(
            incident_id,
            status="error",
            error=str(exc),
            updated_at=_utcnow(),
            completed_at=_utcnow(),
        )


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "incident-response"}


@app.get("/incidents/latest")
def latest_incident():
    latest = store.latest()
    if latest is None:
        return JSONResponse({"detail": "no incidents yet"}, status_code=404)
    return latest


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    item = store.get(incident_id)
    if item is None:
        return JSONResponse({"detail": "not found"}, status_code=404)
    return item


@app.get("/incidents")
def list_incidents():
    return {"incidents": store.list_summaries()}


@app.post("/alerts")
async def receive_alerts(request: Request):
    """Accept Grafana-style webhook payloads. Only firing alerts trigger the assistant."""
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(
            {"accepted": False, "error": "malformed JSON body"},
            status_code=400,
        )

    if payload is None:
        return JSONResponse(
            {"accepted": False, "error": "empty body"},
            status_code=400,
        )

    # Grafana may send {alerts: [...]} or a single alert object, or wrapped variants
    alerts: list[Any]
    if isinstance(payload, dict) and isinstance(payload.get("alerts"), list):
        alerts = payload["alerts"]
    elif isinstance(payload, list):
        alerts = payload
    elif isinstance(payload, dict) and ("status" in payload or "labels" in payload):
        alerts = [payload]
    else:
        return JSONResponse(
            {
                "accepted": True,
                "triggered": [],
                "skipped": [],
                "note": "unrecognized payload shape; nothing triggered",
            },
            status_code=200,
        )

    triggered: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for alert in alerts:
        if not isinstance(alert, dict):
            skipped.append({"reason": "alert is not an object", "alert": alert})
            continue

        status = str(alert.get("status") or "").lower()
        if status != "firing":
            skipped.append(
                {
                    "reason": f"status={status or 'missing'} (only firing triggers assistant)",
                    "alertname": (alert.get("labels") or {}).get("alertname")
                    if isinstance(alert.get("labels"), dict)
                    else None,
                }
            )
            continue

        fp = _fingerprint(alert)
        if _is_duplicate(fp):
            skipped.append(
                {
                    "reason": "duplicate within dedupe window",
                    "fingerprint": fp,
                    "alertname": (alert.get("labels") or {}).get("alertname")
                    if isinstance(alert.get("labels"), dict)
                    else None,
                }
            )
            continue

        incident_id = str(uuid.uuid4())
        labels = alert.get("labels") if isinstance(alert.get("labels"), dict) else {}
        annotations = alert.get("annotations") if isinstance(alert.get("annotations"), dict) else {}

        record = {
            "id": incident_id,
            "status": "accepted",
            "fingerprint": fp,
            "created_at": _utcnow(),
            "updated_at": _utcnow(),
            "alert_name": labels.get("alertname"),
            "labels": labels,
            "annotations": annotations,
            "raw_alert": alert,
            "raw_payload": payload,
            "assistant": None,
            "context": None,
            "error": None,
        }
        store.save(record)

        thread = threading.Thread(
            target=_process_firing_alert,
            args=(incident_id, alert, payload),
            name=f"incident-{incident_id[:8]}",
            daemon=True,
        )
        thread.start()

        triggered.append({"incident_id": incident_id, "fingerprint": fp, "alert_name": labels.get("alertname")})
        logger.info("Accepted firing alert → incident %s (%s)", incident_id, labels.get("alertname"))

    return {
        "accepted": True,
        "triggered": triggered,
        "skipped": skipped,
    }
