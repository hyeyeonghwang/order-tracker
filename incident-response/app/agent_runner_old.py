"""Invoke the Cursor coding assistant CLI in headless mode."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import textwrap
from pathlib import Path
from typing import Any

logger = logging.getLogger("incident-response.agent")

AGENT_BIN = os.getenv("AGENT_BIN", "agent")
AGENT_MODE = os.getenv("AGENT_MODE", "ask")  # ask | plan | "" (full agent)
AGENT_MODEL = os.getenv("AGENT_MODEL", "")
AGENT_FORCE = os.getenv("AGENT_FORCE", "false").lower() in {"1", "true", "yes"}


def _build_prompt(incident_id: str, context: dict[str, Any]) -> str:
    compact = {
        "incident_id": incident_id,
        "alert_name": context.get("alert_name"),
        "status": context.get("status"),
        "labels": context.get("labels"),
        "annotations": context.get("annotations"),
        "affected_endpoint": context.get("affected_endpoint"),
        "service_name": context.get("service_name"),
        "starts_at": context.get("starts_at"),
        "ends_at": context.get("ends_at"),
        "correlation": context.get("correlation"),
        "links": context.get("links"),
        "metrics_query": (context.get("metrics") or {}).get("query"),
        "metrics_result_summary": (context.get("metrics") or {}).get("result"),
        "log_line_count": (context.get("logs") or {}).get("line_count"),
        "log_sample": ((context.get("logs") or {}).get("lines") or [])[:15],
        "trace_errors": (context.get("traces") or {}).get("errors"),
        "trace_search": (context.get("traces") or {}).get("search_result"),
    }
    context_json = json.dumps(compact, indent=2, default=str)
    return textwrap.dedent(
        f"""
        You are the automated incident-response coding assistant for the order-tracker repository.

        Investigate the following Grafana alert incident. Context JSON:

        ```json
        {context_json}
        ```

        Your job:
        1. Determine whether this is a real production incident or a test/false alarm.
        2. If it is explicitly a test notification (e.g. label test=true, or summary says test / no incident to fix), say so clearly and do NOT propose or implement code changes.
        3. Otherwise inspect available logs, traces, metrics links, and repository code to identify the likely root cause.
        4. Propose or implement a fix when appropriate; if no code change is needed, say so explicitly.
        5. Return a concise final incident response with: verdict, root cause (or N/A), actions taken, and next steps.

        Keep the final answer concise.
        """
    ).strip()


def run_coding_assistant(
    *,
    incident_id: str,
    context: dict[str, Any],
    workspace: Path,
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    prompt = _build_prompt(incident_id, context)
    agent_path = shutil.which(AGENT_BIN) or AGENT_BIN

    cmd = [
        agent_path,
        "-p",
        "--trust",
        "--workspace",
        str(workspace),
        "--output-format",
        "text",
    ]
    if AGENT_MODE in {"ask", "plan"}:
        cmd.extend(["--mode", AGENT_MODE])
    if AGENT_FORCE:
        cmd.append("--force")
    if AGENT_MODEL:
        cmd.extend(["--model", AGENT_MODEL])
    cmd.append(prompt)

    logger.info("Invoking coding assistant for incident %s: %s ...", incident_id, " ".join(cmd[:8]))

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            cwd=str(workspace),
            env={**os.environ},
            check=False,
        )
    except FileNotFoundError as exc:
        return {
            "ok": False,
            "error": f"agent binary not found: {exc}",
            "command": cmd[:6],
            "stdout": "",
            "stderr": "",
            "returncode": None,
            "response": None,
        }
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or b"")
        stderr = (exc.stderr or b"")
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        return {
            "ok": False,
            "error": f"agent timed out after {timeout_seconds}s",
            "command": cmd[:6],
            "stdout": stdout,
            "stderr": stderr,
            "returncode": None,
            "response": stdout.strip() or None,
        }

    response = (completed.stdout or "").strip()
    ok = completed.returncode == 0 and bool(response)
    result = {
        "ok": ok,
        "error": None if ok else f"agent exited with code {completed.returncode}",
        "command": cmd[:6] + ["<prompt>"],
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "returncode": completed.returncode,
        "response": response or None,
    }
    if not ok:
        logger.error(
            "Assistant failed for %s rc=%s stderr=%s",
            incident_id,
            completed.returncode,
            (completed.stderr or "")[:500],
        )
    return result
