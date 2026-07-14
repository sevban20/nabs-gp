"""Faz 5 Sprint 37-38: Webhook alarmları — Slack / Teams / Syslog.

Hedefler env ile yapılandırılır; tanımsız hedefler sessizce atlanır:
  SLACK_WEBHOOK_URL, TEAMS_WEBHOOK_URL, SYSLOG_HOST, SYSLOG_PORT
"""
import json
import logging
import logging.handlers
import os

import httpx

logger = logging.getLogger("nabs.notify")


def _severity_emoji(severity: str) -> str:
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(severity, "🔵")


def send_slack(text: str) -> bool:
    from app.core.settings_service import get_setting
    url = get_setting("SLACK_WEBHOOK_URL")
    if not url:
        return False
    resp = httpx.post(url, json={"text": text}, timeout=10.0)
    return resp.status_code < 300


def send_teams(title: str, text: str) -> bool:
    from app.core.settings_service import get_setting
    url = get_setting("TEAMS_WEBHOOK_URL")
    if not url:
        return False
    card = {"@type": "MessageCard", "@context": "http://schema.org/extensions",
            "summary": title, "title": title, "text": text}
    resp = httpx.post(url, json=card, timeout=10.0)
    return resp.status_code < 300


def send_syslog(message: str) -> bool:
    from app.core.settings_service import get_int, get_setting
    host = get_setting("SYSLOG_HOST")
    if not host:
        return False
    port = get_int("SYSLOG_PORT", 514)
    handler = logging.handlers.SysLogHandler(address=(host, port))
    try:
        record = logging.LogRecord("nabs-gp", logging.WARNING, "", 0, message, None, None)
        handler.emit(record)
        return True
    finally:
        handler.close()


def notify_finding(hostname: str, finding: dict) -> dict:
    """Bir güvenlik bulgusunu tüm yapılandırılmış kanallara gönderir."""
    sev = finding.get("severity", "INFO")
    title = f"{_severity_emoji(sev)} NABS-GP [{sev}] {hostname}"
    body = f"{finding.get('title')}\n{finding.get('description', '')[:300]}"
    results = {
        "slack": False, "teams": False, "syslog": False,
    }
    try:
        results["slack"] = send_slack(f"{title}\n{body}")
    except Exception:
        logger.exception("Slack bildirimi başarısız")
    try:
        results["teams"] = send_teams(title, body)
    except Exception:
        logger.exception("Teams bildirimi başarısız")
    try:
        results["syslog"] = send_syslog(json.dumps(
            {"host": hostname, **{k: finding.get(k) for k in ("rule_id", "title", "severity")}}))
    except Exception:
        logger.exception("Syslog bildirimi başarısız")
    return results
