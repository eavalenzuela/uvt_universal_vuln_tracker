def serialize_user(u):
    full_name = " ".join(filter(None, [u.first_name, u.last_name])).strip()
    return {
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "first_name": u.first_name,
        "last_name": u.last_name,
        "full_name": full_name or None,
        "role": u.role,
        "is_active": u.is_active,
        "email_verified": u.email_verified,
        "created_at": u.created_at.isoformat(),
        "updated_at": u.updated_at.isoformat(),
    }


def serialize_user_summary(u):
    full_name = " ".join(filter(None, [u.first_name, u.last_name])).strip()
    return {
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "full_name": full_name or None,
        "is_active": u.is_active,
    }


def serialize_api_token(token):
    return {
        "id": token.id,
        "name": token.name,
        "owner_id": token.owner_id,
        "scopes": token.scopes or [],
        "expires_at": token.expires_at.isoformat() if token.expires_at else None,
        "last_used_at": token.last_used_at.isoformat() if token.last_used_at else None,
        "revoked_at": token.revoked_at.isoformat() if token.revoked_at else None,
        "created_at": token.created_at.isoformat(),
        "updated_at": token.updated_at.isoformat(),
    }
