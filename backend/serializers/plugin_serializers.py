def plugin_run_json(run):
    if not run:
        return None
    return {
        "id": run.id,
        "plugin_id": run.plugin_id,
        "status": run.status,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "error": run.error,
        "stats": run.stats_json,
    }


def redact_storage_path(storage_path):
    if not storage_path:
        return None
    return storage_path.rsplit("/", 1)[-1]


def artifact_json(artifact):
    return {
        "id": artifact.id,
        "plugin_run_id": artifact.plugin_run_id,
        "artifact_type": artifact.artifact_type,
        "storage_path": redact_storage_path(artifact.storage_path),
        "checksum": artifact.checksum,
        "size": artifact.size,
        "content_type": artifact.content_type,
        "created_at": artifact.created_at.isoformat() if artifact.created_at else None,
        "links": [
            {"vulnerability_id": link.vulnerability_id, "product_version_id": link.product_version_id}
            for link in artifact.links
        ],
    }
