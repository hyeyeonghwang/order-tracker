"""Gather incident context from the alert payload and observability backends."""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("incident-response.context")

LOKI_URL = os.getenv("LOKI_URL", "http://loki:3100")
TEMPO_URL = os.getenv("TEMPO_URL", "http://tempo:3200")
PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://prometheus:9090")
GRAFANA_URL = os.getenv("GRAFANA_URL", "http://localhost:3000")
HTTP_TIMEOUT = float(os.getenv("OBSERVABILITY_HTTP_TIMEOUT", "5"))

_ID_PATTERNS = [
    ("trace_id", re.compile(r"\b(?:trace[_-]?id|traceID)=([A-Fa-f0-9]+)\b")),
    ("request_id", re.compile(r"\b(?:request[_-]?id|req[_-]?id)=([A-Za-z0-9-]+)\b")),
    ("correlation_id", re.compile(r"\b(?:correlation[_-]?id)=([A-Za-z0-9-]+)\b")),
]


def _http_get_json(url: str) -> Any | None:
    try:
        with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("GET %s failed: %s", url, exc)
        return None


def _http_get_text(url: str) -> str | None:
    try:
        with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        logger.warning("GET %s failed: %s", url, exc)
        return None


def _extract_endpoint(labels: dict[str, Any], annotations: dict[str, Any]) -> str | None:
    for key in (
        "http_target",
        "http_route",
        "endpoint",
        "path",
        "uri",
    ):
        if labels.get(key):
            return str(labels[key])
    for text in (annotations.get("summary"), annotations.get("description"), annotations.get("dashboard_url")):
        if not text:
            continue
        m = re.search(r"(/api/[^\s)\"']+)", str(text))
        if m:
            return m.group(1)
        m = re.search(r"\b(GET|POST|PATCH|PUT|DELETE)\s+(\S+)", str(text))
        if m:
            return f"{m.group(1)} {m.group(2)}"
    return None


def _extract_ids(*blobs: Any) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {k: [] for k, _ in _ID_PATTERNS}
    found["service_names"] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                lk = str(k).lower()
                if lk in {"trace_id", "traceid"} and v:
                    found["trace_id"].append(str(v))
                elif lk in {"request_id", "req_id", "requestid"} and v:
                    found["request_id"].append(str(v))
                elif lk in {"correlation_id", "correlationid"} and v:
                    found["correlation_id"].append(str(v))
                elif lk in {"service", "service_name", "job"} and v:
                    found["service_names"].append(str(v))
                walk(v)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)
        elif isinstance(obj, str):
            for name, pattern in _ID_PATTERNS:
                for m in pattern.finditer(obj):
                    found[name].append(m.group(1))

    for blob in blobs:
        walk(blob)

    # de-dupe preserving order
    for key, values in list(found.items()):
        seen: set[str] = set()
        uniq: list[str] = []
        for v in values:
            if v not in seen:
                seen.add(v)
                uniq.append(v)
        found[key] = uniq
    return found


def _fetch_loki_logs(service: str | None, endpoint: str | None) -> dict[str, Any]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=15)
    # Prefer service filter; fall back to broad query
    if service:
        query = '{service_name="%s"} |= ``' % service.replace('"', "")
    else:
        query = '{service_name="order-tracker"} |= ``'
    params = urllib.parse.urlencode(
        {
            "query": query,
            "limit": "50",
            "start": str(int(start.timestamp() * 1e9)),
            "end": str(int(end.timestamp() * 1e9)),
        }
    )
    url = f"{LOKI_URL}/loki/api/v1/query_range?{params}"
    data = _http_get_json(url)
    lines: list[str] = []
    if isinstance(data, dict):
        try:
            for stream in data.get("data", {}).get("result", []) or []:
                for _, line in stream.get("values", []) or []:
                    lines.append(line)
                    if endpoint and endpoint not in line and len(lines) > 20:
                        continue
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed parsing Loki response: %s", exc)
    return {
        "url": url,
        "query": query,
        "line_count": len(lines),
        "lines": lines[:40],
        "error": None if data is not None else "loki unreachable or empty",
    }


def _fetch_tempo_traces(trace_ids: list[str], service: str | None) -> dict[str, Any]:
    traces: list[Any] = []
    errors: list[str] = []
    for tid in trace_ids[:3]:
        url = f"{TEMPO_URL}/api/traces/{tid}"
        data = _http_get_json(url)
        if data is None:
            errors.append(f"trace {tid} not found/unreachable")
        else:
            traces.append({"trace_id": tid, "data": data})

    search_url = None
    search_result = None
    if not traces and service:
        q = urllib.parse.urlencode({"service": service, "limit": "5"})
        search_url = f"{TEMPO_URL}/api/search?{q}"
        search_result = _http_get_json(search_url)

    return {
        "searched_trace_ids": trace_ids[:3],
        "traces": traces,
        "search_url": search_url,
        "search_result": search_result,
        "errors": errors,
        "ui_hint": f"{GRAFANA_URL}/explore?orgId=1&left=%7B%22datasource%22:%22tempo%22%7D",
    }


def _fetch_prometheus_hints(endpoint: str | None) -> dict[str, Any]:
    # Use the metric known to exist in this stack
    expr = 'sum by (http_method, http_target, http_status_code) (increase(http_server_duration_milliseconds_count{http_status_code=~"5.."}[15m]))'
    params = urllib.parse.urlencode({"query": expr})
    url = f"{PROMETHEUS_URL}/api/v1/query?{params}"
    data = _http_get_json(url)
    return {
        "query": expr,
        "url": url,
        "result": data,
        "dashboard_url": f"{GRAFANA_URL}/d/order-tracker-5xx/",
        "endpoint_filter": endpoint,
    }


def build_incident_context(
    *,
    alert: dict[str, Any],
    raw_payload: Any,
    workspace: Path,
) -> dict[str, Any]:
    labels = alert.get("labels") if isinstance(alert.get("labels"), dict) else {}
    annotations = alert.get("annotations") if isinstance(alert.get("annotations"), dict) else {}
    endpoint = _extract_endpoint(labels, annotations)
    ids = _extract_ids(alert, raw_payload)
    service = None
    if ids["service_names"]:
        service = ids["service_names"][0]
    elif labels.get("service"):
        service = str(labels["service"])
    else:
        service = "order-tracker"

    started = alert.get("startsAt") or alert.get("starts_at")
    ends = alert.get("endsAt") or alert.get("ends_at")

    logs = _fetch_loki_logs(service, endpoint)
    traces = _fetch_tempo_traces(ids["trace_id"], service)
    metrics = _fetch_prometheus_hints(endpoint)

    return {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "workspace": str(workspace),
        "alert_name": labels.get("alertname"),
        "labels": labels,
        "annotations": annotations,
        "status": alert.get("status"),
        "starts_at": started,
        "ends_at": ends,
        "affected_endpoint": endpoint,
        "service_name": service,
        "correlation": ids,
        "raw_alert": alert,
        "raw_payload": raw_payload,
        "logs": logs,
        "traces": traces,
        "metrics": metrics,
        "links": {
            "grafana": GRAFANA_URL,
            "dashboard": annotations.get("dashboard_url") or metrics["dashboard_url"],
            "runbook": annotations.get("runbook_url"),
            "prometheus_query": metrics["url"],
            "loki_query": logs.get("url"),
        },
    }
