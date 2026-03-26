from backend.services.oidc_mapping import load_role_mapping, map_claims_to_role


# ---------------------------------------------------------------------------
# load_role_mapping
# ---------------------------------------------------------------------------

def test_load_role_mapping_parses_valid_json():
    config = {"OIDC_ROLE_MAPPING": '{"admins": "Admin", "analysts": "Analyst"}'}
    result = load_role_mapping(config)
    assert result == {"admins": "Admin", "analysts": "Analyst"}


def test_load_role_mapping_returns_empty_for_missing_key():
    assert load_role_mapping({}) == {}


def test_load_role_mapping_returns_empty_for_empty_string():
    assert load_role_mapping({"OIDC_ROLE_MAPPING": ""}) == {}


def test_load_role_mapping_returns_empty_for_invalid_json():
    assert load_role_mapping({"OIDC_ROLE_MAPPING": "not json"}) == {}


def test_load_role_mapping_returns_empty_for_non_dict_json():
    assert load_role_mapping({"OIDC_ROLE_MAPPING": '["a", "b"]'}) == {}


def test_load_role_mapping_filters_invalid_roles():
    config = {"OIDC_ROLE_MAPPING": '{"group1": "Admin", "group2": "SuperUser", "group3": "Viewer"}'}
    result = load_role_mapping(config)
    assert result == {"group1": "Admin", "group3": "Viewer"}
    assert "group2" not in result


def test_load_role_mapping_strips_whitespace_from_roles():
    config = {"OIDC_ROLE_MAPPING": '{"group1": " Admin "}'}
    result = load_role_mapping(config)
    assert result == {"group1": "Admin"}


def test_load_role_mapping_skips_non_string_keys_and_values():
    # JSON allows only string keys, but values could be non-string if constructed oddly
    config = {"OIDC_ROLE_MAPPING": '{"group1": 123, "group2": "Analyst"}'}
    result = load_role_mapping(config)
    assert result == {"group2": "Analyst"}


# ---------------------------------------------------------------------------
# map_claims_to_role
# ---------------------------------------------------------------------------

def test_map_claims_returns_mapped_role():
    config = {
        "OIDC_ROLE_MAPPING": '{"uvt-admins": "Admin"}',
        "OIDC_DEFAULT_ROLE": "Viewer",
        "OIDC_GROUPS_CLAIM": "groups",
    }
    assert map_claims_to_role({"groups": ["uvt-admins"]}, config) == "Admin"


def test_map_claims_returns_default_when_no_match():
    config = {
        "OIDC_ROLE_MAPPING": '{"uvt-admins": "Admin"}',
        "OIDC_DEFAULT_ROLE": "Analyst",
        "OIDC_GROUPS_CLAIM": "groups",
    }
    assert map_claims_to_role({"groups": ["unknown-group"]}, config) == "Analyst"


def test_map_claims_returns_viewer_for_invalid_default():
    config = {
        "OIDC_ROLE_MAPPING": "{}",
        "OIDC_DEFAULT_ROLE": "SuperAdmin",
        "OIDC_GROUPS_CLAIM": "groups",
    }
    assert map_claims_to_role({"groups": []}, config) == "Viewer"


def test_map_claims_handles_string_groups():
    config = {
        "OIDC_ROLE_MAPPING": '{"single-group": "Admin"}',
        "OIDC_DEFAULT_ROLE": "Viewer",
        "OIDC_GROUPS_CLAIM": "groups",
    }
    assert map_claims_to_role({"groups": "single-group"}, config) == "Admin"


def test_map_claims_handles_non_iterable_groups():
    config = {
        "OIDC_ROLE_MAPPING": '{"grp": "Admin"}',
        "OIDC_DEFAULT_ROLE": "Viewer",
        "OIDC_GROUPS_CLAIM": "groups",
    }
    assert map_claims_to_role({"groups": 42}, config) == "Viewer"


def test_map_claims_uses_custom_groups_claim():
    config = {
        "OIDC_ROLE_MAPPING": '{"team-a": "Analyst"}',
        "OIDC_DEFAULT_ROLE": "Viewer",
        "OIDC_GROUPS_CLAIM": "team_membership",
    }
    assert map_claims_to_role({"team_membership": ["team-a"]}, config) == "Analyst"


def test_map_claims_returns_first_matched_group():
    config = {
        "OIDC_ROLE_MAPPING": '{"grp-analyst": "Analyst", "grp-admin": "Admin"}',
        "OIDC_DEFAULT_ROLE": "Viewer",
        "OIDC_GROUPS_CLAIM": "groups",
    }
    # Order depends on claim list order, not mapping order
    assert map_claims_to_role({"groups": ["grp-admin", "grp-analyst"]}, config) == "Admin"


def test_map_claims_missing_groups_claim_returns_default():
    config = {
        "OIDC_ROLE_MAPPING": '{"grp": "Admin"}',
        "OIDC_DEFAULT_ROLE": "Analyst",
        "OIDC_GROUPS_CLAIM": "groups",
    }
    assert map_claims_to_role({"email": "user@example.com"}, config) == "Analyst"
