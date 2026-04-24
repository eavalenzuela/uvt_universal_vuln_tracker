from sqlalchemy import asc

from ..models import ProductVersion, SoftwareComponent


def version_json(v: "ProductVersion"):
    return {
        "id": v.id,
        "product_id": v.product_id,
        "version": v.version,
        "release_date": v.release_date.isoformat() if v.release_date else None,
        "is_active": v.is_active,
        "created_at": v.created_at.isoformat(),
        "updated_at": v.updated_at.isoformat(),
    }


def product_json(p: "Product", include_details: bool = False):
    data = {
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "team_id": getattr(p, "team_id", None),
        "team_name": p.team.name if getattr(p, "team", None) else None,
        "created_at": p.created_at.isoformat(),
        "updated_at": p.updated_at.isoformat(),
        "version_count": len(p.versions or []),
    }

    if include_details:
        data["owners"] = [{
            "id": o.user.id,
            "username": o.user.username,
            "email": o.user.email,
            "full_name": " ".join(filter(None, [o.user.first_name, o.user.last_name])).strip() or o.user.username,
        } for o in p.owners]
        data["owner_ids"] = [o.user_id for o in p.owners]
        data["versions"] = [version_json(v) for v in sorted(p.versions, key=lambda x: x.version)]
        if p.creator:
            data["created_by"] = {
                "id": p.creator.id,
                "username": p.creator.username,
                "full_name": " ".join(filter(None, [p.creator.first_name, p.creator.last_name])).strip() or p.creator.username,
            }
        data["controls"] = [{
            "id": link.control.id,
            "name": link.control.name,
            "framework": link.control.framework,
            "description": link.control.description,
            "implementation_status": link.implementation_status,
            "notes": link.notes,
            "mapping_id": link.id,
        } for link in sorted(p.control_links, key=lambda x: (x.control.name or ""))]
        component_count = (
            SoftwareComponent.query.join(ProductVersion, ProductVersion.id == SoftwareComponent.product_version_id)
            .filter(ProductVersion.product_id == p.id)
            .count()
        )
        data["component_count"] = component_count
        component_rows = (
            SoftwareComponent.query.join(ProductVersion, ProductVersion.id == SoftwareComponent.product_version_id)
            .filter(ProductVersion.product_id == p.id)
            .order_by(asc(SoftwareComponent.ecosystem), asc(SoftwareComponent.name), asc(SoftwareComponent.version))
            .all()
        )
        data["components"] = [{
            "id": c.id,
            "product_version_id": c.product_version_id,
            "version_label": c.product_version.version if c.product_version else None,
            "name": c.name,
            "version": c.version,
            "ecosystem": c.ecosystem,
            "purl": c.purl,
            "cpe": c.cpe,
            "dependency_path": (c.metadata_json or {}).get("dependency_path"),
        } for c in component_rows]

    return data
