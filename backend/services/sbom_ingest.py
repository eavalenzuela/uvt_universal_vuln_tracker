from __future__ import annotations

from collections import deque
from typing import Any, Mapping

from backend.database import db
from backend.models import ComponentDependency, ProductVersion, SoftwareComponent, Vulnerability
from backend.services.component_correlation import correlate_vulnerability_to_components


class SbomFormatError(ValueError):
    pass


def ingest_sbom(*, product_version_id: int, sbom_payload: Mapping[str, Any], fmt: str) -> dict[str, int]:
    product_version = ProductVersion.query.get(product_version_id)
    if not product_version:
        raise SbomFormatError("Unknown product version")

    normalized = _parse_cyclonedx(sbom_payload) if fmt == "cyclonedx" else _parse_spdx(sbom_payload)
    component_map = _upsert_components(product_version_id, normalized["components"])
    dependencies_added = _upsert_dependencies(product_version_id, component_map, normalized["dependencies"])

    mapped_vulns = 0
    for vuln in Vulnerability.query.filter(Vulnerability.cve_id.isnot(None)).yield_per(100):
        mapped_vulns += correlate_vulnerability_to_components(
            vuln,
            source=f"sbom:{fmt}",
            cve_id=vuln.cve_id,
            raw_payload=None,
            product_version_id=product_version_id,
        )

    db.session.commit()
    return {
        "components_ingested": len(component_map),
        "dependencies_ingested": dependencies_added,
        "vulnerabilities_mapped": mapped_vulns,
    }


def _upsert_components(product_version_id: int, components: list[dict[str, Any]]) -> dict[str, SoftwareComponent]:
    result: dict[str, SoftwareComponent] = {}
    for item in components:
        bom_ref = item.get("bom_ref") or item.get("purl") or f"{item.get('name')}@{item.get('version') or ''}"
        component = SoftwareComponent.query.filter_by(product_version_id=product_version_id, bom_ref=bom_ref).first()
        if component is None:
            component = SoftwareComponent(product_version_id=product_version_id, bom_ref=bom_ref, name=item["name"])
            db.session.add(component)
        component.name = item["name"]
        component.version = item.get("version")
        component.ecosystem = item.get("ecosystem")
        component.purl = item.get("purl")
        component.cpe = item.get("cpe")
        component.component_type = item.get("component_type") or "library"
        component.metadata_json = item.get("metadata") or {}
        result[bom_ref] = component
    db.session.flush()
    return result


def _upsert_dependencies(product_version_id: int, component_map: dict[str, SoftwareComponent], dependency_refs: dict[str, list[str]]) -> int:
    ComponentDependency.query.filter_by(product_version_id=product_version_id).delete(synchronize_session=False)
    added = 0
    for parent_ref, children_refs in dependency_refs.items():
        parent = component_map.get(parent_ref)
        if not parent:
            continue
        depth_map = _compute_depths(parent_ref, dependency_refs)
        for child_ref in children_refs:
            child = component_map.get(child_ref)
            if not child:
                continue
            depth = depth_map.get(child_ref, 1)
            path = f"{parent_ref} > {child_ref}"
            db.session.add(ComponentDependency(
                product_version_id=product_version_id,
                parent_component_id=parent.id,
                child_component_id=child.id,
                dependency_path=path,
                depth=depth,
                is_direct=(depth <= 1),
            ))
            child_meta = dict(child.metadata_json or {})
            child_meta.setdefault("dependency_path", path)
            child.metadata_json = child_meta
            added += 1
    return added


def _compute_depths(root: str, graph: dict[str, list[str]]) -> dict[str, int]:
    depths: dict[str, int] = {}
    queue: deque[tuple[str, int]] = deque([(root, 0)])
    visited = {root}
    while queue:
        node, depth = queue.popleft()
        for child in graph.get(node, []):
            next_depth = depth + 1
            if child not in depths or next_depth < depths[child]:
                depths[child] = next_depth
            if child not in visited:
                visited.add(child)
                queue.append((child, next_depth))
    return depths


def _parse_cyclonedx(payload: Mapping[str, Any]) -> dict[str, Any]:
    components_payload = payload.get("components")
    if not isinstance(components_payload, list):
        raise SbomFormatError("CycloneDX payload must contain components array")

    components: list[dict[str, Any]] = []
    for c in components_payload:
        if not isinstance(c, Mapping):
            continue
        name = c.get("name")
        if not isinstance(name, str) or not name:
            continue
        properties = c.get("properties") if isinstance(c.get("properties"), list) else []
        cves = [p.get("value") for p in properties if isinstance(p, Mapping) and p.get("name") == "uvt:cve"]
        components.append({
            "bom_ref": c.get("bom-ref") or c.get("bom_ref"),
            "name": name,
            "version": c.get("version"),
            "ecosystem": _ecosystem_from_purl(c.get("purl")),
            "purl": c.get("purl"),
            "cpe": c.get("cpe"),
            "component_type": c.get("type") or "library",
            "metadata": {"cves": [item for item in cves if isinstance(item, str)]},
        })

    deps: dict[str, list[str]] = {}
    for d in payload.get("dependencies") or []:
        if not isinstance(d, Mapping):
            continue
        ref = d.get("ref")
        depends_on = d.get("dependsOn")
        if isinstance(ref, str) and isinstance(depends_on, list):
            deps[ref] = [item for item in depends_on if isinstance(item, str)]

    return {"components": components, "dependencies": deps}


def _parse_spdx(payload: Mapping[str, Any]) -> dict[str, Any]:
    packages = payload.get("packages")
    if not isinstance(packages, list):
        raise SbomFormatError("SPDX payload must contain packages array")

    components: list[dict[str, Any]] = []
    for pkg in packages:
        if not isinstance(pkg, Mapping):
            continue
        name = pkg.get("name")
        if not isinstance(name, str) or not name:
            continue
        external_refs = pkg.get("externalRefs") if isinstance(pkg.get("externalRefs"), list) else []
        purl = None
        cpe = None
        for ref in external_refs:
            if not isinstance(ref, Mapping):
                continue
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
            if ref.get("referenceType") in {"cpe22Type", "cpe23Type"}:
                cpe = ref.get("referenceLocator")
        components.append({
            "bom_ref": pkg.get("SPDXID"),
            "name": name,
            "version": pkg.get("versionInfo"),
            "ecosystem": _ecosystem_from_purl(purl),
            "purl": purl,
            "cpe": cpe,
            "component_type": "library",
            "metadata": {},
        })

    deps: dict[str, list[str]] = {}
    for rel in payload.get("relationships") or []:
        if not isinstance(rel, Mapping):
            continue
        if rel.get("relationshipType") != "DEPENDS_ON":
            continue
        parent = rel.get("spdxElementId")
        child = rel.get("relatedSpdxElement")
        if isinstance(parent, str) and isinstance(child, str):
            deps.setdefault(parent, []).append(child)

    return {"components": components, "dependencies": deps}


def _ecosystem_from_purl(purl: Any) -> str | None:
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    value = purl[len("pkg:"):]
    parts = value.split("/")
    if not parts:
        return None
    return parts[0].split("@")[0] or None
