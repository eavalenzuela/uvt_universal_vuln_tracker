import json
from typing import Iterable

VALID_ROLES = {"Admin", "Analyst", "Viewer"}


def load_role_mapping(config):
    raw = config.get("OIDC_ROLE_MAPPING", "")
    if not raw:
        return {}
    try:
        mapping = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(mapping, dict):
        return {}

    normalized = {}
    for group, role in mapping.items():
        if not isinstance(group, str) or not isinstance(role, str):
            continue
        clean_role = role.strip()
        if clean_role in VALID_ROLES:
            normalized[group] = clean_role
    return normalized


def map_claims_to_role(claims: dict, config) -> str:
    default_role = config.get("OIDC_DEFAULT_ROLE", "Viewer")
    if default_role not in VALID_ROLES:
        default_role = "Viewer"

    groups_claim = config.get("OIDC_GROUPS_CLAIM", "groups")
    groups = claims.get(groups_claim, [])
    if isinstance(groups, str):
        groups = [groups]
    if not isinstance(groups, Iterable):
        groups = []

    mapping = load_role_mapping(config)
    for group in groups:
        mapped = mapping.get(group)
        if mapped:
            return mapped

    return default_role
