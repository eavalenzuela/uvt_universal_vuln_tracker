"""Service layer for AttackVector CRUD and VulnerabilityAttackVector mappings."""

from __future__ import annotations

from sqlalchemy import asc

from ..database import db
from ..models import AttackVector, Vulnerability, VulnerabilityAttackVector, ProductVersion
from ..api.validation import ValidationError, parse_int
from ..services.audit import record_audit


# ---------------------------------------------------------------------------
# AttackVector CRUD
# ---------------------------------------------------------------------------

def list_attack_vectors() -> list[AttackVector]:
    """Return all attack vectors ordered by name."""
    return AttackVector.query.order_by(asc(AttackVector.name)).all()


def create_attack_vector(name: str, description: str | None = None) -> AttackVector:
    """Create a new AttackVector, commit, and return it."""
    attack_vector = AttackVector(name=name, description=description)
    db.session.add(attack_vector)
    db.session.commit()
    return attack_vector


def get_attack_vector(vector_id: int) -> AttackVector:
    """Fetch an AttackVector by id or raise 404."""
    return AttackVector.query.get_or_404(vector_id)


def update_attack_vector(vector_id: int, data: dict) -> AttackVector:
    """Update name/description on an existing AttackVector.

    Raises ``ValidationError`` if *name* is present but empty.
    """
    vector = AttackVector.query.get_or_404(vector_id)

    if "name" in data:
        name = (data.get("name") or "").strip()
        if not name:
            raise ValidationError(error="name cannot be empty", field="name")
        vector.name = name

    if "description" in data:
        vector.description = data.get("description")

    db.session.commit()
    return vector


def delete_attack_vector(vector_id: int) -> dict:
    """Delete an AttackVector and return a snapshot dict of the old values."""
    vector = AttackVector.query.get_or_404(vector_id)
    snapshot = {"name": vector.name, "description": vector.description}
    record_audit(
        "DELETE", "attack_vectors", vector.id,
        old_values=snapshot,
    )
    db.session.delete(vector)
    db.session.commit()
    return snapshot


# ---------------------------------------------------------------------------
# VulnerabilityAttackVector mappings
# ---------------------------------------------------------------------------

def list_vulnerability_attack_vectors(vuln_id: int) -> list[VulnerabilityAttackVector]:
    """Return all attack-vector mappings for a given vulnerability."""
    Vulnerability.query.get_or_404(vuln_id)
    return VulnerabilityAttackVector.query.filter_by(vulnerability_id=vuln_id).all()


def attach_vulnerability_attack_vectors(vuln_id: int, mappings: list[dict]) -> int:
    """Validate and create attack-vector mappings for a vulnerability.

    Returns the number of newly added mappings.
    Raises ``ValidationError`` for invalid attack-vector or product-version ids.
    """
    Vulnerability.query.get_or_404(vuln_id)
    added = 0

    for item in mappings:
        attack_vector_id = item.get("attack_vector_id")
        product_version_id = item.get("product_version_id")

        if not attack_vector_id:
            raise ValidationError(error="attack_vector_id is required", field="attack_vector_id")

        parsed_attack_vector_id = parse_int(
            attack_vector_id, field="attack_vector_id", minimum=1, required=True,
        )
        vector = db.session.get(AttackVector, parsed_attack_vector_id)
        if not vector:
            raise ValidationError(
                error=f"Invalid attack vector {attack_vector_id}",
                field="attack_vector_id",
            )

        pv_id = (
            parse_int(product_version_id, field="product_version_id", minimum=1)
            if product_version_id is not None
            else None
        )
        if pv_id is not None:
            pv = db.session.get(ProductVersion, pv_id)
            if not pv:
                raise ValidationError(
                    error=f"Invalid product version {pv_id}",
                    field="product_version_id",
                )

        existing = VulnerabilityAttackVector.query.filter_by(
            vulnerability_id=vuln_id,
            attack_vector_id=vector.id,
            product_version_id=pv_id,
        ).first()
        if existing:
            continue

        db.session.add(VulnerabilityAttackVector(
            vulnerability_id=vuln_id,
            attack_vector_id=vector.id,
            product_version_id=pv_id,
        ))
        added += 1

    db.session.commit()
    return added


def update_vulnerability_attack_vector(
    vuln_id: int, mapping_id: int, data: dict,
) -> VulnerabilityAttackVector:
    """Update fields on a vulnerability ↔ attack-vector mapping.

    Raises ``ValidationError`` for invalid ids.
    """
    Vulnerability.query.get_or_404(vuln_id)
    mapping = VulnerabilityAttackVector.query.filter_by(
        id=mapping_id, vulnerability_id=vuln_id,
    ).first_or_404()

    if "attack_vector_id" in data:
        vector_id = data.get("attack_vector_id")
        parsed_vector_id = (
            parse_int(vector_id, field="attack_vector_id", minimum=1)
            if vector_id
            else None
        )
        vector = db.session.get(AttackVector, parsed_vector_id) if parsed_vector_id else None
        if not vector:
            raise ValidationError(
                error=f"Invalid attack vector {vector_id}",
                field="attack_vector_id",
            )
        mapping.attack_vector_id = vector.id

    if "product_version_id" in data:
        pv_id = data.get("product_version_id")
        if pv_id is None:
            mapping.product_version_id = None
        else:
            parsed_pv_id = parse_int(
                pv_id, field="product_version_id", minimum=1, required=True,
            )
            pv = db.session.get(ProductVersion, parsed_pv_id)
            if not pv:
                raise ValidationError(
                    error=f"Invalid product version {pv_id}",
                    field="product_version_id",
                )
            mapping.product_version_id = pv.id

    db.session.commit()
    return mapping


def delete_vulnerability_attack_vector(vuln_id: int, mapping_id: int) -> None:
    """Delete a vulnerability ↔ attack-vector mapping."""
    Vulnerability.query.get_or_404(vuln_id)
    mapping = VulnerabilityAttackVector.query.filter_by(
        id=mapping_id, vulnerability_id=vuln_id,
    ).first_or_404()
    db.session.delete(mapping)
    db.session.commit()


# ---------------------------------------------------------------------------
# Serialization helper
# ---------------------------------------------------------------------------

def serialize_mapping(mapping: VulnerabilityAttackVector) -> dict:
    """Serialize a VulnerabilityAttackVector mapping to a JSON-friendly dict.

    Resolves the associated ProductVersion to include product details.
    """
    pv = (
        db.session.get(ProductVersion, mapping.product_version_id)
        if mapping.product_version_id
        else None
    )
    return {
        "id": mapping.id,
        "vulnerability_id": mapping.vulnerability_id,
        "attack_vector_id": mapping.attack_vector_id,
        "attack_vector_name": mapping.attack_vector.name if mapping.attack_vector else None,
        "attack_vector_description": mapping.attack_vector.description if mapping.attack_vector else None,
        "product_version_id": mapping.product_version_id,
        "product_id": pv.product_id if pv else None,
        "product_name": pv.product.name if getattr(pv, "product", None) else None,
        "version": pv.version if pv else None,
        "release_date": pv.release_date.isoformat() if getattr(pv, "release_date", None) else None,
    }
