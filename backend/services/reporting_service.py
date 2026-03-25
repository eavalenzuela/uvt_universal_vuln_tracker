from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import desc

from ..database import db
from ..models import Product, ProductVersion, Vulnerability, VulnerabilityVersion
from ..services.vulnerability_query import build_vulnerability_query

SEVERITY_WEIGHTS = {"Critical": 10, "High": 6, "Medium": 3, "Low": 1, "None": 0}
OPEN_STATUSES = {"Open", "In Progress"}


def parse_csv_ints(value):
    if not value:
        return []
    parts = str(value).split(",")
    parsed = []
    for part in parts:
        item = part.strip()
        if not item:
            continue
        try:
            parsed.append(int(item))
        except ValueError as exc:
            raise ValueError("Filter values must be integer ids") from exc
    return parsed


def parse_iso_datetime(value, *, field):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise ValueError(f"{field} must be ISO-8601 datetime") from exc


def range_start(range_value):
    now = datetime.now(timezone.utc)
    if range_value == "Month to date":
        return datetime(now.year, now.month, 1)
    if range_value == "Quarter to date":
        quarter_start_month = (now.month - 1) // 3 * 3 + 1
        return datetime(now.year, quarter_start_month, 1)
    if range_value:
        import re

        match = re.match(r"Last\s+(\d+)\s+days", range_value, flags=re.IGNORECASE)
        if match:
            return now - timedelta(days=int(match.group(1)))
    return now - timedelta(days=14)


def dashboard_aggregate(filters, *, group_by="severity", range_value="Last 14 days"):
    q, _ = build_vulnerability_query(filters, base_query=Vulnerability.query)
    total = q.count()

    rows = q.with_entities(
        Vulnerability.id,
        Vulnerability.severity,
        Vulnerability.status,
        Vulnerability.assigned_to,
        Vulnerability.updated_at,
    ).all()

    by_severity = {}
    by_status = {}
    group_totals = {}
    group_attr = {
        "Severity": "severity",
        "Status": "status",
        "Assignee": "assigned_to",
    }.get(group_by, "severity")

    start = range_start(range_value)
    end = datetime.now(timezone.utc)
    days = max(1, (end.date() - start.date()).days + 1)
    buckets = [{"date": (start.date() + timedelta(days=i)).isoformat(), "count": 0} for i in range(days)]

    for _, severity, status, assigned_to, updated_at in rows:
        severity_key = severity or "Unknown"
        status_key = status or "Unknown"
        by_severity[severity_key] = by_severity.get(severity_key, 0) + 1
        by_status[status_key] = by_status.get(status_key, 0) + 1

        group_value = {
            "severity": severity_key,
            "status": status_key,
            "assigned_to": str(assigned_to) if assigned_to is not None else "Unassigned",
        }[group_attr]
        group_totals[group_value] = group_totals.get(group_value, 0) + 1

        if updated_at:
            updated_dt = updated_at if isinstance(updated_at, datetime) else datetime.fromisoformat(str(updated_at))
            if start <= updated_dt <= end:
                idx = (updated_dt.date() - start.date()).days
                if 0 <= idx < len(buckets):
                    buckets[idx]["count"] += 1

    return {
        "total": total,
        "by_severity": by_severity,
        "by_status": by_status,
        "group_by": group_by,
        "group_totals": group_totals,
        "trend": {
            "range": range_value,
            "start_date": start.date().isoformat(),
            "end_date": end.date().isoformat(),
            "buckets": buckets,
        },
    }


def risk_trends(filters):
    bucket = (filters.get("bucket") or "week").lower()
    if bucket not in {"day", "week", "month"}:
        raise ValueError("bucket must be one of day, week, month")

    start = parse_iso_datetime(filters.get("start_date"), field="start_date") or range_start(filters.get("range") or "Last 30 days")
    end = parse_iso_datetime(filters.get("end_date"), field="end_date") or datetime.now(timezone.utc)
    if start > end:
        raise ValueError("start_date must be <= end_date")

    product_ids = parse_csv_ints(filters.get("product_ids"))
    product_version_ids = parse_csv_ints(filters.get("product_version_ids"))

    q = (
        db.session.query(
            Vulnerability.updated_at,
            Vulnerability.severity,
            Vulnerability.status,
            Vulnerability.sla_due_at,
            Product.id,
            Product.name,
            ProductVersion.id,
            ProductVersion.version,
        )
        .select_from(Vulnerability)
        .join(VulnerabilityVersion, VulnerabilityVersion.vulnerability_id == Vulnerability.id)
        .join(ProductVersion, ProductVersion.id == VulnerabilityVersion.product_version_id)
        .join(Product, Product.id == ProductVersion.product_id)
        .filter(Vulnerability.updated_at >= start)
        .filter(Vulnerability.updated_at <= end)
    )

    if product_ids:
        q = q.filter(Product.id.in_(product_ids))
    if product_version_ids:
        q = q.filter(ProductVersion.id.in_(product_version_ids))

    rows = q.all()
    now = datetime.now(timezone.utc)
    grouped = {}

    for updated_at, severity, status, sla_due_at, product_id, product_name, product_version_id, product_version in rows:
        if not updated_at:
            continue
        if bucket == "day":
            bucket_value = updated_at.strftime("%Y-%m-%d")
        elif bucket == "week":
            iso_year, iso_week, _ = updated_at.isocalendar()
            bucket_value = f"{iso_year}-W{iso_week:02d}"
        else:
            bucket_value = updated_at.strftime("%Y-%m")

        key = (product_id, product_version_id, bucket_value)
        entry = grouped.get(key)
        if entry is None:
            entry = {
                "product_id": product_id,
                "product_name": product_name,
                "product_version_id": product_version_id,
                "product_version": product_version,
                "bucket": bucket_value,
                "open_critical_count": 0,
                "overdue_sla_count": 0,
                "weighted_risk_score": 0,
            }
            grouped[key] = entry

        is_open = status in OPEN_STATUSES
        if is_open and severity == "Critical":
            entry["open_critical_count"] += 1
        if is_open and sla_due_at and sla_due_at < now:
            entry["overdue_sla_count"] += 1
        entry["weighted_risk_score"] += SEVERITY_WEIGHTS.get(severity, 0)

    trend_rows = sorted(grouped.values(), key=lambda item: (item["product_name"] or "", item["product_version"] or "", item["bucket"]))
    top_risk = sorted(trend_rows, key=lambda item: (item["weighted_risk_score"], item["open_critical_count"], item["overdue_sla_count"]), reverse=True)[:5]
    return {
        "bucket": bucket,
        "start_date": start.isoformat(),
        "end_date": end.isoformat(),
        "items": trend_rows,
        "top_risk_products": top_risk,
    }
