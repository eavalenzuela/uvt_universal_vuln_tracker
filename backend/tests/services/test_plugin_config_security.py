from backend.api.plugins import _merge_plugin_config
from backend.plugins.config import MASKED_VALUE, is_masked_value, mask_config


def test_is_masked_value_accepts_supported_placeholders_only():
    assert is_masked_value("****") is True
    assert is_masked_value(" ****** ") is True

    assert is_masked_value("***") is False
    assert is_masked_value("not-masked") is False
    assert is_masked_value(True) is False
    assert is_masked_value(None) is False


def test_mask_config_masks_nested_sensitive_keys_and_schema_declared_secrets():
    schema = {
        "fields": {
            "api_token": {"type": "string", "secret": True},
            "enabled": {"type": "boolean", "required": False},
        }
    }
    config = {
        "api_token": "top-secret-token",
        "enabled": True,
        "nested": {
            "password": "super-secret-password",
            "url": "https://example.test",
            "deep": {"client_secret": "value", "flag": False},
        },
        "items": [
            {"private_key": "abc123", "name": "first"},
            {"apikey": "xyz", "count": 3},
        ],
    }

    masked = mask_config(config, schema)

    assert masked["api_token"] == MASKED_VALUE
    assert masked["enabled"] is True
    assert masked["nested"]["password"] == MASKED_VALUE
    assert masked["nested"]["url"] == "https://example.test"
    assert masked["nested"]["deep"]["client_secret"] == MASKED_VALUE
    assert masked["nested"]["deep"]["flag"] is False
    assert masked["items"][0]["private_key"] == MASKED_VALUE
    assert masked["items"][0]["name"] == "first"
    assert masked["items"][1]["apikey"] == MASKED_VALUE
    assert masked["items"][1]["count"] == 3


def test_mask_config_preserves_empty_or_none_secret_values_for_round_trip_inputs():
    schema = {"fields": {"api_token": {"secret": True}}}

    assert mask_config({"api_token": ""}, schema)["api_token"] == ""
    assert mask_config({"api_token": None}, schema)["api_token"] is None


def test_merge_plugin_config_preserves_existing_secret_when_masked_placeholder_submitted():
    existing = {
        "api_token": "stored-secret",
        "enabled": True,
        "nested": {
            "password": "stored-nested-secret",
            "region": "us-east-1",
            "flags": {"client_secret": "deep-secret", "verify_ssl": True},
        },
    }
    updates = {
        "api_token": MASKED_VALUE,
        "enabled": False,
        "nested": {
            "password": "******",
            "region": "eu-west-1",
            "flags": {"client_secret": MASKED_VALUE, "verify_ssl": False},
        },
    }

    merged = _merge_plugin_config(existing, updates)

    assert merged["api_token"] == "stored-secret"
    assert merged["enabled"] is False
    assert merged["nested"]["password"] == "stored-nested-secret"
    assert merged["nested"]["region"] == "eu-west-1"
    assert merged["nested"]["flags"]["client_secret"] == "deep-secret"
    assert merged["nested"]["flags"]["verify_ssl"] is False


def test_merge_plugin_config_ignores_masked_placeholder_for_new_unknown_key():
    existing = {"name": "plugin"}
    updates = {"new_secret": MASKED_VALUE, "name": "plugin-updated"}

    merged = _merge_plugin_config(existing, updates)

    assert "new_secret" not in merged
    assert merged["name"] == "plugin-updated"


def test_mask_then_merge_round_trip_keeps_existing_secrets_while_updating_non_secrets():
    schema = {
        "fields": {
            "api_key": {"secret": True},
            "enabled": {"type": "boolean"},
            "endpoint": {"type": "string"},
        }
    }
    stored_config = {
        "api_key": "real-secret",
        "enabled": True,
        "endpoint": "https://old.example",
        "nested": {"password": "nested-secret", "mode": "strict"},
    }

    masked_for_client = mask_config(stored_config, schema)
    client_payload = {
        "api_key": masked_for_client["api_key"],
        "enabled": False,
        "endpoint": "https://new.example",
        "nested": {
            "password": masked_for_client["nested"]["password"],
            "mode": "relaxed",
        },
    }

    merged = _merge_plugin_config(stored_config, client_payload)

    assert merged["api_key"] == "real-secret"
    assert merged["enabled"] is False
    assert merged["endpoint"] == "https://new.example"
    assert merged["nested"]["password"] == "nested-secret"
    assert merged["nested"]["mode"] == "relaxed"
