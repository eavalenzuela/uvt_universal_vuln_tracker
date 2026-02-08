from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from itertools import zip_longest
from typing import Any

from packaging.version import InvalidVersion, Version
from sqlalchemy import asc

from backend.models import ComponentDependency, ProductVersion, SoftwareComponent


@dataclass(frozen=True)
class _ComparableComponent:
    id: int
    product_version_id: int
    name: str
    version: str | None
    ecosystem: str | None
    purl: str | None
    cpe: str | None
    bom_ref: str | None
    component_type: str | None


@dataclass(frozen=True)
class _ComparableDependency:
    id: int
    parent_component_id: int
    child_component_id: int
    dependency_path: str | None
    depth: int
    is_direct: bool


def compare_product_version_components(from_product_version_id: int, to_product_version_id: int) -> dict[str, Any]:
    from_version = ProductVersion.query.get_or_404(from_product_version_id)
    to_version = ProductVersion.query.get_or_404(to_product_version_id)

    from_components = _load_components(from_version.id)
    to_components = _load_components(to_version.id)

    from_groups = _group_by_name_and_ecosystem(from_components)
    to_groups = _group_by_name_and_ecosystem(to_components)

    added_components: list[dict[str, Any]] = []
    removed_components: list[dict[str, Any]] = []
    changed_components: list[dict[str, Any]] = []
    version_upgrades: list[dict[str, Any]] = []
    version_downgrades: list[dict[str, Any]] = []

    all_keys = sorted(set(from_groups.keys()) | set(to_groups.keys()))
    for key in all_keys:
        before = sorted(from_groups.get(key, []), key=_component_sort_key)
        after = sorted(to_groups.get(key, []), key=_component_sort_key)

        for old_component, new_component in zip_longest(before, after):
            if old_component is None and new_component is not None:
                added_components.append(_component_json(new_component))
                continue
            if new_component is None and old_component is not None:
                removed_components.append(_component_json(old_component))
                continue
            if old_component is None or new_component is None:
                continue

            change = _component_change(old_component, new_component)
            if change is not None:
                changed_components.append(change)

            version_delta = _component_version_delta(old_component, new_component)
            if version_delta is None:
                continue
            if version_delta["direction"] == "upgrade":
                version_upgrades.append(version_delta)
            elif version_delta["direction"] == "downgrade":
                version_downgrades.append(version_delta)

    dependency_delta = _dependency_delta(from_version.id, to_version.id, from_components, to_components)

    return {
        "from_product_version": _version_json(from_version),
        "to_product_version": _version_json(to_version),
        "summary": {
            "added_components": len(added_components),
            "removed_components": len(removed_components),
            "changed_components": len(changed_components),
            "version_upgrades": len(version_upgrades),
            "version_downgrades": len(version_downgrades),
            "dependency_edges_added": len(dependency_delta["added"]),
            "dependency_edges_removed": len(dependency_delta["removed"]),
            "dependency_edges_changed": len(dependency_delta["changed"]),
        },
        "components": {
            "added": added_components,
            "removed": removed_components,
            "changed": changed_components,
        },
        "version_deltas": {
            "upgrades": version_upgrades,
            "downgrades": version_downgrades,
        },
        "dependency_graph": dependency_delta,
    }


def _load_components(product_version_id: int) -> list[_ComparableComponent]:
    rows = (
        SoftwareComponent.query
        .filter_by(product_version_id=product_version_id)
        .order_by(asc(SoftwareComponent.ecosystem), asc(SoftwareComponent.name), asc(SoftwareComponent.version))
        .all()
    )
    return [
        _ComparableComponent(
            id=row.id,
            product_version_id=row.product_version_id,
            name=row.name,
            version=row.version,
            ecosystem=row.ecosystem,
            purl=row.purl,
            cpe=row.cpe,
            bom_ref=row.bom_ref,
            component_type=row.component_type,
        )
        for row in rows
    ]


def _group_by_name_and_ecosystem(components: list[_ComparableComponent]) -> dict[tuple[str, str], list[_ComparableComponent]]:
    grouped: dict[tuple[str, str], list[_ComparableComponent]] = defaultdict(list)
    for component in components:
        grouped[_component_group_key(component)].append(component)
    return grouped


def _component_group_key(component: _ComparableComponent) -> tuple[str, str]:
    return (
        (component.ecosystem or "").strip().lower(),
        (component.name or "").strip().lower(),
    )


def _component_sort_key(component: _ComparableComponent) -> tuple[str, str, str, str, str]:
    return (
        (component.version or ""),
        (component.purl or ""),
        (component.cpe or ""),
        (component.bom_ref or ""),
        (component.component_type or ""),
    )


def _component_json(component: _ComparableComponent) -> dict[str, Any]:
    return {
        "id": component.id,
        "product_version_id": component.product_version_id,
        "name": component.name,
        "version": component.version,
        "ecosystem": component.ecosystem,
        "purl": component.purl,
        "cpe": component.cpe,
        "bom_ref": component.bom_ref,
        "component_type": component.component_type,
    }


def _component_change(old_component: _ComparableComponent, new_component: _ComparableComponent) -> dict[str, Any] | None:
    changed_fields: dict[str, dict[str, Any]] = {}
    for field in ("version", "purl", "cpe", "bom_ref", "component_type"):
        old_value = getattr(old_component, field)
        new_value = getattr(new_component, field)
        if old_value != new_value:
            changed_fields[field] = {"from": old_value, "to": new_value}

    if not changed_fields:
        return None

    return {
        "component_key": {
            "name": old_component.name,
            "ecosystem": old_component.ecosystem,
        },
        "from": _component_json(old_component),
        "to": _component_json(new_component),
        "changes": changed_fields,
    }


def _component_version_delta(old_component: _ComparableComponent, new_component: _ComparableComponent) -> dict[str, Any] | None:
    if old_component.version == new_component.version:
        return None

    relation = _compare_versions(old_component.version, new_component.version)
    direction = "upgrade" if relation < 0 else "downgrade"

    return {
        "name": old_component.name,
        "ecosystem": old_component.ecosystem,
        "from_component_id": old_component.id,
        "to_component_id": new_component.id,
        "from_version": old_component.version,
        "to_version": new_component.version,
        "direction": direction,
    }


def _compare_versions(old_version: str | None, new_version: str | None) -> int:
    old_text = (old_version or "").strip()
    new_text = (new_version or "").strip()
    if old_text == new_text:
        return 0

    try:
        old_parsed = Version(old_text)
        new_parsed = Version(new_text)
        if old_parsed < new_parsed:
            return -1
        if old_parsed > new_parsed:
            return 1
        return 0
    except InvalidVersion:
        pass

    if old_text.lower() < new_text.lower():
        return -1
    return 1


def _dependency_delta(
    from_product_version_id: int,
    to_product_version_id: int,
    from_components: list[_ComparableComponent],
    to_components: list[_ComparableComponent],
) -> dict[str, list[dict[str, Any]]]:
    from_component_index = {component.id: component for component in from_components}
    to_component_index = {component.id: component for component in to_components}

    from_dependencies = _load_dependencies(from_product_version_id)
    to_dependencies = _load_dependencies(to_product_version_id)

    from_edges = {
        _dependency_identity(dep, from_component_index): dep
        for dep in from_dependencies
        if _dependency_identity(dep, from_component_index) is not None
    }
    to_edges = {
        _dependency_identity(dep, to_component_index): dep
        for dep in to_dependencies
        if _dependency_identity(dep, to_component_index) is not None
    }

    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []

    all_edge_keys = sorted(set(from_edges.keys()) | set(to_edges.keys()))
    for edge_key in all_edge_keys:
        old_dep = from_edges.get(edge_key)
        new_dep = to_edges.get(edge_key)

        if old_dep is None and new_dep is not None:
            added.append(_dependency_json(new_dep, to_component_index))
            continue
        if new_dep is None and old_dep is not None:
            removed.append(_dependency_json(old_dep, from_component_index))
            continue
        if old_dep is None or new_dep is None:
            continue

        if (
            old_dep.depth != new_dep.depth
            or old_dep.is_direct != new_dep.is_direct
            or (old_dep.dependency_path or "") != (new_dep.dependency_path or "")
        ):
            changed.append({
                "edge": {
                    "parent": edge_key[0],
                    "child": edge_key[1],
                },
                "from": _dependency_json(old_dep, from_component_index),
                "to": _dependency_json(new_dep, to_component_index),
            })

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def _load_dependencies(product_version_id: int) -> list[_ComparableDependency]:
    rows = ComponentDependency.query.filter_by(product_version_id=product_version_id).all()
    return [
        _ComparableDependency(
            id=row.id,
            parent_component_id=row.parent_component_id,
            child_component_id=row.child_component_id,
            dependency_path=row.dependency_path,
            depth=row.depth,
            is_direct=row.is_direct,
        )
        for row in rows
    ]


def _dependency_identity(
    dependency: _ComparableDependency,
    component_index: dict[int, _ComparableComponent],
) -> tuple[tuple[str, str], tuple[str, str]] | None:
    parent = component_index.get(dependency.parent_component_id)
    child = component_index.get(dependency.child_component_id)
    if parent is None or child is None:
        return None
    return (
        (
            (parent.ecosystem or "").lower(),
            (parent.name or "").lower(),
        ),
        (
            (child.ecosystem or "").lower(),
            (child.name or "").lower(),
        ),
    )


def _dependency_json(
    dependency: _ComparableDependency,
    component_index: dict[int, _ComparableComponent],
) -> dict[str, Any]:
    parent = component_index.get(dependency.parent_component_id)
    child = component_index.get(dependency.child_component_id)

    return {
        "id": dependency.id,
        "dependency_path": dependency.dependency_path,
        "depth": dependency.depth,
        "is_direct": dependency.is_direct,
        "parent": _component_json(parent) if parent else None,
        "child": _component_json(child) if child else None,
    }


def _version_json(product_version: ProductVersion) -> dict[str, Any]:
    return {
        "id": product_version.id,
        "product_id": product_version.product_id,
        "version": product_version.version,
        "release_date": product_version.release_date.isoformat() if product_version.release_date else None,
        "is_active": product_version.is_active,
    }
