"""Global search API — search across vulnerabilities, products, and comments."""

from flask import Blueprint, jsonify, request
from sqlalchemy import or_

from ..auth import login_required
from ..database import db
from ..models import Vulnerability, Product, VulnerabilityComment, User

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


@bp.get("/api/search")
@login_required
def global_search():
    """Search across vulnerabilities, products, and comments.
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
        return jsonify({"error": "Search query must be at least 2 characters"}), 400

    like = f"%{q}%"

    # Vulnerabilities: title, cve_id, description
    vulns = (
        Vulnerability.query
        .filter(or_(
            Vulnerability.title.ilike(like),
            Vulnerability.cve_id.ilike(like),
            Vulnerability.description.ilike(like),
        ))
        .order_by(Vulnerability.updated_at.desc())
        .limit(MAX_RESULTS_PER_TYPE)
        .all()
    )

    # Products: name, description
    products = (
        Product.query
        .filter(or_(
            Product.name.ilike(like),
            Product.description.ilike(like),
        ))
        .order_by(Product.name)
        .limit(MAX_RESULTS_PER_TYPE)
        .all()
    )

    # Comments: body (join to get author name)
    comment_rows = (
        db.session.query(VulnerabilityComment, User.username)
        .join(User, VulnerabilityComment.author_id == User.id)
        .filter(VulnerabilityComment.body.ilike(like))
        .order_by(VulnerabilityComment.created_at.desc())
        .limit(MAX_RESULTS_PER_TYPE)
        .all()
    )

    return jsonify({
        "query": q,
        "vulnerabilities": [_vuln_hit(v) for v in vulns],
        "products": [_product_hit(p) for p in products],
        "comments": [_comment_hit(c, author) for c, author in comment_rows],
    })
