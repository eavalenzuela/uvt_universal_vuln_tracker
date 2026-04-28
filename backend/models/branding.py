"""Organization-level PDF report branding (F17 Slice 3).

Singleton row (id=1) holds primary color, footer text, and a path to the
uploaded logo on disk under ``instance/branding/``. We don't shard by team —
branding is org-global; team scope only changes which data is rendered.
"""

import base64
import mimetypes
import os
from datetime import datetime, timezone
from pathlib import Path

from ..database import db, TZDateTime


class OrganizationBranding(db.Model):
    __tablename__ = "organization_branding"

    id = db.Column(db.Integer, primary_key=True)
    primary_color = db.Column(db.String(7), nullable=False, default="#2563eb")
    footer_text = db.Column(db.String(255), nullable=False, default="")
    logo_path = db.Column(db.String(1024))
    updated_at = db.Column(
        TZDateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def logo_data_uri(self) -> str | None:
        """Return the logo as a base64 data URI, or None if no logo is set."""
        if not self.logo_path:
            return None
        path = Path(self.logo_path)
        if not path.exists():
            return None
        mime, _ = mimetypes.guess_type(str(path))
        if mime is None:
            mime = "image/png"
        try:
            data = path.read_bytes()
        except OSError:
            return None
        return f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}"

    @classmethod
    def get_or_create(cls):
        row = cls.query.first()
        if row is None:
            row = cls()
            db.session.add(row)
            db.session.commit()
        return row
