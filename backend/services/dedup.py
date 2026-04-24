import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import or_

from ..database import db
from ..models import (
    AuditLog,
    Notification,
    NotificationDeliveryCheckpoint,
    NotificationDeliveryLog,
    PluginRunArtifactLink,
    Vulnerability,
    VulnerabilityAttackVector,
    VulnerabilityComment,
    VulnerabilityComponent,
    VulnerabilitySource,
    VulnerabilityTerminalImpact,
    VulnerabilityVersion,
    VulnerabilityWatcher,
)


def normalize_title(value: str | None) -> str:
    text = (value or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _token_set(value: str | None) -> set[str]:
    normalized = normalize_title(value)
    return {token for token in normalized.split(" ") if token}


def _jaccard_similarity(left: set[Any], right: set[Any]) -> float:
    if not left and not right:
        return 0.0
    union = left | right
    if not union:
        return 0.0
    return len(left & right) / len(union)


def _extract_version_ids(vuln: Vulnerability) -> set[int]:
    return {mapping.product_version_id for mapping in (vuln.versions or []) if mapping.product_version_id}


def _extract_component_ids(vuln: Vulnerability) -> set[int]:
    return {mapping.component_id for mapping in (vuln.affected_components or []) if mapping.component_id}


def score_duplicate_candidate(vulnerability: Vulnerability, candidate: Vulnerability) -> dict[str, Any]:
    score = 0.0
    reasons: list[str] = []

    if vulnerability.cve_id and candidate.cve_id and vulnerability.cve_id == candidate.cve_id:
        score += 50
        reasons.append("same_cve_id")

    base_title = normalize_title(vulnerability.title)
    candidate_title = normalize_title(candidate.title)
    if base_title and candidate_title:
        if base_title == candidate_title:
            score += 25
            reasons.append("same_normalized_title")
        else:
            title_overlap = _jaccard_similarity(_token_set(base_title), _token_set(candidate_title))
            if title_overlap > 0:
                score += round(title_overlap * 20, 2)
                reasons.append("title_token_overlap")

    if vulnerability.severity and candidate.severity and vulnerability.severity == candidate.severity:
        score += 10
        reasons.append("same_severity")

    version_overlap = _jaccard_similarity(_extract_version_ids(vulnerability), _extract_version_ids(candidate))
    if version_overlap > 0:
        score += round(version_overlap * 15, 2)
        reasons.append("overlapping_affected_versions")

    component_overlap = _jaccard_similarity(_extract_component_ids(vulnerability), _extract_component_ids(candidate))
    if component_overlap > 0:
        score += round(component_overlap * 15, 2)
        reasons.append("overlapping_components")

    return {
        "candidate_id": candidate.id,
        "score": round(score, 2),
        "reasons": reasons,
        "version_overlap": round(version_overlap, 3),
        "component_overlap": round(component_overlap, 3),
    }


def list_merge_candidates(vulnerability: Vulnerability, *, limit: int = 20) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 100))
    possible = (
        Vulnerability.query
        .filter(Vulnerability.id != vulnerability.id)
        .filter(or_(Vulnerability.is_merged.is_(False), Vulnerability.is_merged.is_(None)))
        .all()
    )

    scored: list[dict[str, Any]] = []
    for candidate in possible:
        details = score_duplicate_candidate(vulnerability, candidate)
        if details["score"] <= 0:
            continue
        scored.append({
            **details,
            "candidate": {
                "id": candidate.id,
                "cve_id": candidate.cve_id,
                "title": candidate.title,
                "severity": candidate.severity,
                "status": candidate.status,
                "is_merged": bool(candidate.is_merged),
                "merged_into_id": candidate.merged_into_id,
            },
        })

    scored.sort(key=lambda row: (row["score"], row["candidate"]["id"]), reverse=True)
    return scored[:limit]


def _merge_unique_link_rows(source_model, target_vuln_id: int, source_vuln_id: int, uniqueness_fields: list[str]):
    target_rows = source_model.query.filter_by(vulnerability_id=target_vuln_id).all()
    target_keys = {
        tuple(getattr(row, field) for field in uniqueness_fields): row
        for row in target_rows
    }
    source_rows = source_model.query.filter_by(vulnerability_id=source_vuln_id).all()

    for row in source_rows:
        key = tuple(getattr(row, field) for field in uniqueness_fields)
        if key in target_keys:
            db.session.delete(row)
            continue
        row.vulnerability_id = target_vuln_id


def _merge_vulnerability_versions(target_vuln_id: int, source_vuln_id: int):
    target_rows = {
        row.product_version_id: row
        for row in VulnerabilityVersion.query.filter_by(vulnerability_id=target_vuln_id).all()
    }
    for row in VulnerabilityVersion.query.filter_by(vulnerability_id=source_vuln_id).all():
        existing = target_rows.get(row.product_version_id)
        if not existing:
            row.vulnerability_id = target_vuln_id
            continue
        existing.affected = bool(existing.affected or row.affected)
        if not existing.fixed_in_version and row.fixed_in_version:
            existing.fixed_in_version = row.fixed_in_version
        if not existing.notes and row.notes:
            existing.notes = row.notes
        db.session.delete(row)


def _merge_watchers(target_vuln_id: int, source_vuln_id: int):
    existing_watchers = {
        row.user_id
        for row in VulnerabilityWatcher.query.filter_by(vulnerability_id=target_vuln_id).all()
    }
    for row in VulnerabilityWatcher.query.filter_by(vulnerability_id=source_vuln_id).all():
        if row.user_id in existing_watchers:
            db.session.delete(row)
            continue
        row.vulnerability_id = target_vuln_id


def _relink_records_by_vulnerability(target_vuln_id: int, source_vuln_id: int):
    VulnerabilityComment.query.filter_by(vulnerability_id=source_vuln_id).update(
        {VulnerabilityComment.vulnerability_id: target_vuln_id},
        synchronize_session=False,
    )
    Notification.query.filter_by(vulnerability_id=source_vuln_id).update(
        {Notification.vulnerability_id: target_vuln_id},
        synchronize_session=False,
    )
    NotificationDeliveryLog.query.filter_by(vulnerability_id=source_vuln_id).update(
        {NotificationDeliveryLog.vulnerability_id: target_vuln_id},
        synchronize_session=False,
    )
    PluginRunArtifactLink.query.filter_by(vulnerability_id=source_vuln_id).update(
        {PluginRunArtifactLink.vulnerability_id: target_vuln_id},
        synchronize_session=False,
    )

    existing_checkpoints = {
        checkpoint.rule_id
        for checkpoint in NotificationDeliveryCheckpoint.query.filter_by(vulnerability_id=target_vuln_id).all()
    }
    for checkpoint in NotificationDeliveryCheckpoint.query.filter_by(vulnerability_id=source_vuln_id).all():
        if checkpoint.rule_id in existing_checkpoints:
            db.session.delete(checkpoint)
            continue
        checkpoint.vulnerability_id = target_vuln_id

    AuditLog.query.filter(
        AuditLog.table_name == "vulnerabilities",
        AuditLog.record_id == source_vuln_id,
    ).update({AuditLog.record_id: target_vuln_id}, synchronize_session=False)


def merge_vulnerabilities(*, target: Vulnerability, source: Vulnerability, actor_id: int, reason: str | None = None) -> dict[str, Any]:
    if target.id == source.id:
        raise ValueError("source and target must be different")
    if source.is_merged:
        raise ValueError("source vulnerability is already merged")
    if target.is_merged:
        raise ValueError("target vulnerability is already merged into another record")
    if target.merged_into_id == source.id:
        raise ValueError("merge would create a cycle: target was previously merged into source")

    _merge_vulnerability_versions(target.id, source.id)
    _merge_unique_link_rows(VulnerabilityComponent, target.id, source.id, ["component_id", "source"])
    _merge_unique_link_rows(VulnerabilityAttackVector, target.id, source.id, ["attack_vector_id", "product_version_id"])
    _merge_unique_link_rows(VulnerabilityTerminalImpact, target.id, source.id, ["terminal_impact_id"])
    _merge_unique_link_rows(VulnerabilitySource, target.id, source.id, ["source", "source_id"])

    _merge_watchers(target.id, source.id)
    _relink_records_by_vulnerability(target.id, source.id)

    now = datetime.now(timezone.utc).isoformat()

    target_meta = dict(target.merge_metadata_json or {})
    merged_sources = list(target_meta.get("merged_source_ids") or [])
    if source.id not in merged_sources:
        merged_sources.append(source.id)
    target_meta.update({
        "last_merge_at": now,
        "last_merged_by": actor_id,
        "merged_source_ids": merged_sources,
    })
    target.merge_metadata_json = target_meta

    source.is_merged = True
    source.merged_into_id = target.id
    source.status = "Closed"
    source.merge_metadata_json = {
        "merged_at": now,
        "merged_by": actor_id,
        "merged_into_id": target.id,
        "reason": reason,
    }

    source_refs = list(source.references_json or [])
    source_refs.append({
        "type": "merged_redirect",
        "target_vulnerability_id": target.id,
        "merged_at": now,
    })
    source.references_json = source_refs

    target_refs = list(target.references_json or [])
    target_refs.append({
        "type": "merged_from",
        "source_vulnerability_id": source.id,
        "merged_at": now,
        "reason": reason,
    })
    target.references_json = target_refs

    db.session.flush()

    return {
        "target_vulnerability_id": target.id,
        "source_vulnerability_id": source.id,
        "merged_at": now,
    }
