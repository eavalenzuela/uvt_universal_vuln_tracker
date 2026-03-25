from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..models import SlaPolicy, VulnerabilityVersion

DEFAULT_SLA_POLICY = {
    "global": {
        "Critical": 7,
        "High": 14,
        "Medium": 30,
        "Low": 60,
        "None": 90,
    },
    "overrides": [],
    "due_soon_days": 7,
}


SEVERITIES = {"Critical", "High", "Medium", "Low", "None"}


def normalize_sla_policy(payload: dict | None) -> dict:
    payload = payload or {}
    global_map = dict(DEFAULT_SLA_POLICY["global"])
    for severity, value in (payload.get("global") or {}).items():
        if severity not in SEVERITIES:
            continue
        try:
            days = int(value)
        except (TypeError, ValueError):
            continue
        if days > 0:
            global_map[severity] = days

    overrides = []
    for raw in (payload.get("overrides") or []):
        if not isinstance(raw, dict):
            continue
        severity = raw.get("severity")
        product_id = raw.get("product_id")
        days = raw.get("days")
        if severity not in SEVERITIES:
            continue
        try:
            product_id = int(product_id)
            days = int(days)
        except (TypeError, ValueError):
            continue
        if product_id <= 0 or days <= 0:
            continue
        overrides.append({"product_id": product_id, "severity": severity, "days": days})

    try:
        due_soon_days = int(payload.get("due_soon_days", DEFAULT_SLA_POLICY["due_soon_days"]))
    except (TypeError, ValueError):
        due_soon_days = DEFAULT_SLA_POLICY["due_soon_days"]
    if due_soon_days < 0:
        due_soon_days = DEFAULT_SLA_POLICY["due_soon_days"]

    return {
        "global": global_map,
        "overrides": overrides,
        "due_soon_days": due_soon_days,
    }


def get_sla_policy() -> dict:
    row = SlaPolicy.query.order_by(SlaPolicy.id.desc()).first()
    if not row or not isinstance(row.policy_json, dict):
        return normalize_sla_policy(None)
    return normalize_sla_policy(row.policy_json)


def resolve_sla_days(vulnerability, policy: dict | None = None) -> int:
    policy = normalize_sla_policy(policy) if policy is not None else get_sla_policy()
    severity = vulnerability.severity if vulnerability.severity in SEVERITIES else "Medium"
    selected_days = int(policy["global"].get(severity, DEFAULT_SLA_POLICY["global"]["Medium"]))

    product_ids = {
        mapping.product_version.product_id
        for mapping in (vulnerability.versions or [])
        if mapping.product_version is not None
    }

    if not product_ids and getattr(vulnerability, "id", None):
        for mapping in VulnerabilityVersion.query.filter_by(vulnerability_id=vulnerability.id).all():
            if mapping.product_version is not None:
                product_ids.add(mapping.product_version.product_id)

    for override in policy.get("overrides", []):
        if override.get("severity") == severity and override.get("product_id") in product_ids:
            selected_days = min(selected_days, int(override.get("days", selected_days)))

    return selected_days


def recompute_vulnerability_sla(vulnerability, policy: dict | None = None):
    created_at = vulnerability.created_at or datetime.now(timezone.utc)
    days = resolve_sla_days(vulnerability, policy=policy)
    vulnerability.sla_due_at = created_at + timedelta(days=days)


def compute_sla_state(vulnerability, policy: dict | None = None) -> str:
    if not vulnerability.sla_due_at:
        return "on_track"
    policy = normalize_sla_policy(policy) if policy is not None else get_sla_policy()
    now = datetime.now(timezone.utc)
    if vulnerability.sla_due_at < now:
        return "breached"
    due_soon_days = int(policy.get("due_soon_days", DEFAULT_SLA_POLICY["due_soon_days"]))
    if vulnerability.sla_due_at <= now + timedelta(days=due_soon_days):
        return "due_soon"
    return "on_track"
