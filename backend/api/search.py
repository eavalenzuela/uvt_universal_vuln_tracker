"""Global search API — search across vulnerabilities, products, components, and comments."""

from flask import Blueprint, jsonify, request
from sqlalchemy import or_

from ..auth import login_required
from ..database import db
from ..models import Product, ProductVersion, SoftwareComponent, User, Vulnerability, VulnerabilityComment
from ..services.team_scope import team_ids_for_user, team_scope
from .validation import error_response, escape_like

bp = Blueprint("search_api", __name__, url_prefix="/api")

MAX_RESULTS_PER_TYPE = 10


def _vuln_hit(v):
    return {
        "id": v.id,
        "cve_id": v.cve_id,
        "title": v.title,
        "severity": v.severity,
        "status": v.status,
    }


def _product_hit(p):
    return {
        "id": p.id,
        "name": p.name,
        "description": (p.description or "")[:120],
    }


def _comment_hit(c, author_name):
    return {
        "id": c.id,
        "vulnerability_id": c.vulnerability_id,
        "body": (c.body or "")[:200],
        "author": author_name,
        "created_at": c.created_at.isoformat() if c.created_at else None,
    }


def _component_hit(component, product_id, product_name, version_label):
    return {
        "id": component.id,
        "name": component.name,
        "version": component.version,
        "ecosystem": component.ecosystem,
        "product_id": product_id,
        "product_name": product_name,
        "product_version": version_label,
    }


@bp.get("/search")
@login_required
def global_search():
    """Search across vulnerabilities, products, components, and comments.
    ---
    get:
      summary: Global search
      security:
        - BearerAuth: []
      parameters:
        - in: query
          name: q
          required: true
          schema:
            type: string
            minLength: 2
          description: Search query (min 2 characters)
      responses:
        200:
          description: Search results grouped by entity type
          content:
            application/json:
              schema:
                type: object
                properties:
                  query:
                    type: string
                  vulnerabilities:
                    type: array
                  products:
                    type: array
                  components:
                    type: array
                  comments:
                    type: array
        400:
          description: Query too short
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    q = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return error_response("Search query must be at least 2 characters", field="q")

    # Escape LIKE wildcards so a query of "_" or "%" matches literally instead
    # of matching every row.
    like = f"%{escape_like(q)}%"
    user = request.user

    # Vulnerabilities: title, cve_id, description (scoped, shared-pool included)
    vulns = (
        team_scope(Vulnerability.query, Vulnerability, user, allow_null_team=True)
        .filter(or_(
            Vulnerability.title.ilike(like, escape="\\"),
            Vulnerability.cve_id.ilike(like, escape="\\"),
            Vulnerability.description.ilike(like, escape="\\"),
        ))
        .order_by(Vulnerability.updated_at.desc())
        .limit(MAX_RESULTS_PER_TYPE)
        .all()
    )

    # Products: name, description (scoped by team)
    products = (
        team_scope(Product.query, Product, user)
        .filter(or_(
            Product.name.ilike(like, escape="\\"),
            Product.description.ilike(like, escape="\\"),
        ))
        .order_by(Product.name)
        .limit(MAX_RESULTS_PER_TYPE)
        .all()
    )

    # Comments: visibility inherited from the parent vulnerability.
    comment_query = (
        db.session.query(VulnerabilityComment, User.username)
        .join(User, VulnerabilityComment.author_id == User.id)
        .filter(VulnerabilityComment.body.ilike(like, escape="\\"))
    )
    if user and user.role != "Admin":
        ids = team_ids_for_user(user)
        comment_query = comment_query.join(
            Vulnerability, VulnerabilityComment.vulnerability_id == Vulnerability.id,
        )
        if ids:
            comment_query = comment_query.filter(
                or_(Vulnerability.team_id.in_(ids), Vulnerability.team_id.is_(None))
            )
        else:
            comment_query = comment_query.filter(Vulnerability.team_id.is_(None))

    comment_rows = (
        comment_query.order_by(VulnerabilityComment.created_at.desc())
        .limit(MAX_RESULTS_PER_TYPE)
        .all()
    )

    # Software components: name, ecosystem, purl. Visibility inherits from the
    # owning product's team.
    component_query = (
        db.session.query(SoftwareComponent, Product.id, Product.name, ProductVersion.version)
        .join(ProductVersion, SoftwareComponent.product_version_id == ProductVersion.id)
        .join(Product, ProductVersion.product_id == Product.id)
        .filter(or_(
            SoftwareComponent.name.ilike(like, escape="\\"),
            SoftwareComponent.ecosystem.ilike(like, escape="\\"),
            SoftwareComponent.purl.ilike(like, escape="\\"),
        ))
    )
    if user and user.role != "Admin":
        ids = team_ids_for_user(user)
        if ids:
            component_query = component_query.filter(
                or_(Product.team_id.in_(ids), Product.team_id.is_(None))
            )
        else:
            component_query = component_query.filter(Product.team_id.is_(None))

    component_rows = (
        component_query.order_by(SoftwareComponent.name)
        .limit(MAX_RESULTS_PER_TYPE)
        .all()
    )

    return jsonify({
        "query": q,
        "vulnerabilities": [_vuln_hit(v) for v in vulns],
        "products": [_product_hit(p) for p in products],
        "components": [
            _component_hit(component, product_id, product_name, version_label)
            for component, product_id, product_name, version_label in component_rows
        ],
        "comments": [_comment_hit(c, author) for c, author in comment_rows],
    })
