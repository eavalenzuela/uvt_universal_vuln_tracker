"""Tests for the OpenAPI spec endpoint and Swagger UI."""

import pytest


def test_openapi_json_returns_valid_spec(client):
    resp = client.get("/api/openapi.json")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["openapi"] == "3.0.3"
    assert data["info"]["title"] == "Universal Vulnerability Tracker API"
    assert "paths" in data
    assert len(data["paths"]) > 50
    assert "components" in data
    assert "schemas" in data["components"]
    assert "BearerAuth" in data["components"]["securitySchemes"]


def test_openapi_json_contains_expected_paths(client):
    data = client.get("/api/openapi.json").get_json()
    paths = data["paths"]
    assert "/api/auth/login" in paths
    assert "/api/vulnerabilities" in paths
    assert "/api/products" in paths
    assert "/api/health" in paths


def test_openapi_json_paths_have_summaries(client):
    data = client.get("/api/openapi.json").get_json()
    login = data["paths"]["/api/auth/login"]["post"]
    assert "summary" in login
    assert login["summary"]


def test_openapi_json_has_tags(client):
    data = client.get("/api/openapi.json").get_json()
    tag_names = [t["name"] for t in data["tags"]]
    assert "Auth" in tag_names
    assert "Vulnerabilities" in tag_names
    assert "Products" in tag_names
    assert "Plugins" in tag_names


def test_swagger_ui_page_loads(client):
    resp = client.get("/api/docs/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "swagger" in body.lower()
