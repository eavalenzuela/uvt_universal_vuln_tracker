from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from typing import Any, Callable

MASKED_VALUE = "****"
_MASKED_VALUES = {MASKED_VALUE, "******"}

_SENSITIVE_KEY_MARKERS = (
    "secret",
    "token",
    "password",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "client_secret",
)

SecretStore = Callable[[str], str | None] | Mapping[str, str]


def is_masked_value(value: Any) -> bool:
    return isinstance(value, str) and value.strip() in _MASKED_VALUES


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in _SENSITIVE_KEY_MARKERS)


def _normalize_fields(schema: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    if not schema:
        return {}

    fields = schema.get("fields", schema)
    normalized: dict[str, dict[str, Any]] = {}
    if isinstance(fields, Mapping):
        for name, spec in fields.items():
            if isinstance(spec, Mapping):
                normalized[str(name)] = dict(spec)
            else:
                normalized[str(name)] = {"type": spec}
    elif isinstance(fields, Sequence) and not isinstance(fields, (str, bytes, bytearray)):
        for entry in fields:
            if not isinstance(entry, Mapping):
                raise ValueError("config_schema fields must be mapping objects")
            name = entry.get("name")
            if not name:
                raise ValueError("config_schema field entries must include a name")
            normalized[str(name)] = dict(entry)
    else:
        raise ValueError("config_schema fields must be a mapping or list")
    return normalized


def validate_config_schema(schema: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    normalized = _normalize_fields(schema)
    for name, spec in normalized.items():
        if not isinstance(spec, Mapping):
            raise ValueError(f"config_schema field '{name}' must be a mapping")
        for flag in ("required", "secret"):
            if flag in spec and not isinstance(spec[flag], bool):
                raise ValueError(f"config_schema field '{name}' has invalid '{flag}' flag")
    return normalized


def _resolve_secret_value(
    value: Any,
    *,
    env: Mapping[str, str],
    secret_store: SecretStore | None,
) -> Any:
    if not isinstance(value, Mapping):
        return value
    if "env" in value:
        env_key = str(value.get("env") or "").strip()
        if not env_key:
            raise ValueError("env secret reference requires a non-empty key")
        return env.get(env_key)
    if "secret_store" in value:
        secret_key = str(value.get("secret_store") or "").strip()
        if not secret_key:
            raise ValueError("secret_store reference requires a non-empty key")
        if secret_store is None:
            raise ValueError("secret_store reference provided but no secret store configured")
        if callable(secret_store):
            return secret_store(secret_key)
        return secret_store.get(secret_key)
    return value


def resolve_config_secrets(
    config: Mapping[str, Any],
    schema: Mapping[str, Any] | None,
    *,
    env: Mapping[str, str] | None = None,
    secret_store: SecretStore | None = None,
) -> dict[str, Any]:
    env_map = env or os.environ
    normalized = _normalize_fields(schema or {})
    resolved: dict[str, Any] = dict(config)
    for name, spec in normalized.items():
        if not spec.get("secret"):
            continue
        if name not in resolved:
            continue
        resolved[name] = _resolve_secret_value(resolved[name], env=env_map, secret_store=secret_store)
    return resolved


def apply_config_defaults(
    config: Mapping[str, Any],
    schema: Mapping[str, Any] | None,
) -> dict[str, Any]:
    normalized = _normalize_fields(schema or {})
    updated: dict[str, Any] = dict(config)
    for name, spec in normalized.items():
        if name not in updated and "default" in spec:
            updated[name] = spec["default"]
    return updated


_TRUE_STRINGS = frozenset({"1", "true", "yes", "on"})
_FALSE_STRINGS = frozenset({"0", "false", "no", "off", ""})


def coerce_config_types(
    config: Mapping[str, Any],
    schema: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Coerce config values to the types their schema fields declare.

    Nothing used to enforce declared types. Every value written through the
    admin UI arrives as a string — that is what an HTML form produces — so a
    field declared ``type: integer`` happily stored ``"30"``, and the first
    thing that used it as a number blew up. The KEV feed plugin died on
    ``urlopen(timeout="30")`` with ``TypeError: 'str' object cannot be
    interpreted as an integer``, reported only as "artifact persistence
    failed".

    Coercion runs on read as well as write, so configs already stored with the
    wrong type are repaired rather than needing a migration.

    Values that cannot be coerced raise ``ValueError`` naming the field, which
    surfaces as a normal validation error instead of a runtime crash.
    """
    normalized = _normalize_fields(schema or {})
    coerced: dict[str, Any] = dict(config)

    for name, spec in normalized.items():
        if name not in coerced:
            continue
        value = coerced[name]
        declared = str(spec.get("type") or "string").lower()

        # Empty optional fields and unresolved secrets stay as they are.
        if value is None or (isinstance(value, str) and not value.strip() and declared != "string"):
            continue
        if spec.get("secret") and is_masked_value(value):
            continue

        try:
            if declared == "integer" and not isinstance(value, bool):
                coerced[name] = int(str(value).strip())
            elif declared == "number" and not isinstance(value, bool):
                coerced[name] = float(str(value).strip())
            elif declared == "boolean":
                if isinstance(value, bool):
                    continue
                text = str(value).strip().lower()
                if text in _TRUE_STRINGS:
                    coerced[name] = True
                elif text in _FALSE_STRINGS:
                    coerced[name] = False
                else:
                    raise ValueError(text)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Plugin config field '{name}' must be {declared}, got {value!r}"
            ) from exc

    return coerced


def validate_required_config(
    config: Mapping[str, Any],
    schema: Mapping[str, Any] | None,
) -> None:
    normalized = _normalize_fields(schema or {})
    missing: list[str] = []
    for name, spec in normalized.items():
        if not spec.get("required"):
            continue
        value = config.get(name)
        if value in (None, "") or (spec.get("secret") and is_masked_value(value)):
            missing.append(name)
    if missing:
        missing_list = ", ".join(sorted(missing))
        raise ValueError(f"Missing required plugin config values: {missing_list}")


def prepare_plugin_config(
    config: Mapping[str, Any] | None,
    schema: Mapping[str, Any] | None,
    *,
    env: Mapping[str, str] | None = None,
    secret_store: SecretStore | None = None,
) -> dict[str, Any]:
    validated_schema = validate_config_schema(schema or {})
    current = dict(config or {})
    current = apply_config_defaults(current, validated_schema)
    current = resolve_config_secrets(current, validated_schema, env=env, secret_store=secret_store)
    # After secret resolution, so a value pulled from the environment (always a
    # string) is coerced too.
    current = coerce_config_types(current, validated_schema)
    validate_required_config(current, validated_schema)
    return current


def mask_config(config: Any, schema: Mapping[str, Any] | None = None) -> Any:
    normalized = _normalize_fields(schema or {})

    def _mask_value(value: Any, key: str | None = None) -> Any:
        if isinstance(value, Mapping):
            return {item_key: _mask_value(item, item_key) for item_key, item in value.items()}
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [_mask_value(item, key) for item in value]
        if key and (normalized.get(key, {}).get("secret") or is_sensitive_key(str(key))):
            return MASKED_VALUE if value not in (None, "") else value
        return value

    if isinstance(config, Mapping):
        return {key: _mask_value(value, key) for key, value in config.items()}
    return _mask_value(config)
