from backend.auth import create_user
from backend.database import db
from backend.models import PluginRunArtifact, PluginRunArtifactLink, Vulnerability
from backend.plugins.base import BasePlugin


class ImmediateExecutor:
    def submit(self, fn, *args, **kwargs):
        fn(*args, **kwargs)
        return object()


class ArtifactPlugin(BasePlugin):
    plugin_id = "artifact-plugin"
    display_name = "Artifact Plugin"

    def run(self):
        return self.config["result"]


def _register_artifact_plugin(app):
    with app.app_context():
        app.extensions["plugin_registry"].register(ArtifactPlugin)


def test_plugin_artifact_persistence_and_retrieval_permissions(app, client, admin_user, auth_header, monkeypatch, tmp_path):
    _register_artifact_plugin(app)
    artifact_path = tmp_path / "scan-log.json"
    artifact_path.write_text('{"status":"ok"}')

    monkeypatch.setattr("backend.plugins.runner.get_plugin_run_executor", lambda: ImmediateExecutor())

    admin_headers = auth_header(admin_user)
    run_resp = client.post(
        "/api/plugins/artifact-plugin/run",
        headers=admin_headers,
        json={
            "config": {
                "result": {
                    "stats": {"items_processed": 1},
                    "artifacts": [
                        {
                            "artifact_type": "scan_log",
                            "storage_path": str(artifact_path),
                            "checksum": "abc123",
                            "size": artifact_path.stat().st_size,
                            "content_type": "application/json",
                        }
                    ],
                }
            }
        },
    )
    assert run_resp.status_code == 202
    run_id = run_resp.get_json()["id"]

    list_resp = client.get(f"/api/plugins/runs/{run_id}/artifacts", headers=admin_headers)
    assert list_resp.status_code == 200
    artifacts = list_resp.get_json()
    assert len(artifacts) == 1
    artifact_id = artifacts[0]["id"]
    assert artifacts[0]["storage_path"] == "scan-log.json"

    with app.app_context():
        viewer = create_user("viewer_artifacts", "viewer_artifacts@example.com", "secret-pass-12", role="Viewer")
        db.session.refresh(viewer)

    viewer_headers = auth_header(viewer)
    forbidden = client.get(f"/api/plugins/artifacts/{artifact_id}/download", headers=viewer_headers)
    assert forbidden.status_code == 403

    download = client.get(f"/api/plugins/artifacts/{artifact_id}/download", headers=admin_headers)
    assert download.status_code == 200
    assert download.data == b'{"status":"ok"}'


def test_plugin_artifact_save_failure_sets_partial_failed(app, client, admin_user, auth_header, monkeypatch, tmp_path):
    _register_artifact_plugin(app)
    artifact_path = tmp_path / "broken.json"
    artifact_path.write_text("broken")

    monkeypatch.setattr("backend.plugins.runner.get_plugin_run_executor", lambda: ImmediateExecutor())

    run_resp = client.post(
        "/api/plugins/artifact-plugin/run",
        headers=auth_header(admin_user),
        json={
            "config": {
                "result": {
                    "artifacts": [
                        {
                            "artifact_type": "raw",
                            "storage_path": str(artifact_path),
                            "vulnerability_ids": ["not-an-int"],
                        }
                    ]
                }
            }
        },
    )
    assert run_resp.status_code == 202
    run_id = run_resp.get_json()["id"]

    status_resp = client.get(f"/api/plugins/runs/{run_id}", headers=auth_header(admin_user))
    payload = status_resp.get_json()
    assert payload["status"] == "partial_failed"
    # The message now carries the underlying exception. It used to be replaced
    # wholesale with the bare string, which told an operator nothing about what
    # actually failed and left no trace of it anywhere.
    assert payload["error"].startswith("artifact persistence failed")
    assert ":" in payload["error"], "the real exception should be included"

    with app.app_context():
        assert PluginRunArtifact.query.filter_by(plugin_run_id=run_id).count() == 0


def test_plugin_artifact_linkage_query_traceability(app, client, admin_user, auth_header, monkeypatch, sample_product_version, tmp_path):
    _register_artifact_plugin(app)
    _, product_version = sample_product_version

    with app.app_context():
        vuln = Vulnerability(title="Artifact linked vuln", severity="Low", status="Open", created_by=admin_user.id)
        db.session.add(vuln)
        db.session.commit()
        vuln_id = vuln.id

    artifact_path = tmp_path / "trace.log"
    artifact_path.write_text("trace")

    monkeypatch.setattr("backend.plugins.runner.get_plugin_run_executor", lambda: ImmediateExecutor())

    run_resp = client.post(
        "/api/plugins/artifact-plugin/run",
        headers=auth_header(admin_user),
        json={
            "config": {
                "result": {
                    "artifacts": [
                        {
                            "artifact_type": "attachment",
                            "storage_path": str(artifact_path),
                            "vulnerability_ids": [vuln_id],
                            "product_version_ids": [product_version.id],
                        }
                    ]
                }
            }
        },
    )
    run_id = run_resp.get_json()["id"]

    with app.app_context():
        links = (
            PluginRunArtifactLink.query.join(PluginRunArtifact)
            .filter(PluginRunArtifact.plugin_run_id == run_id, PluginRunArtifactLink.vulnerability_id == vuln_id)
            .all()
        )
        assert len(links) == 1
        assert links[0].product_version_id is None

        version_links = (
            PluginRunArtifactLink.query.join(PluginRunArtifact)
            .filter(
                PluginRunArtifact.plugin_run_id == run_id,
                PluginRunArtifactLink.product_version_id == product_version.id,
            )
            .all()
        )
        assert len(version_links) == 1
        assert version_links[0].vulnerability_id is None
