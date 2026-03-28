"""Task status API — check progress of background Celery tasks."""

from flask import Blueprint, jsonify, current_app
from ..auth import login_required
from .validation import error_response

bp = Blueprint("tasks", __name__)


@bp.get("/api/tasks/<task_id>")
@login_required
def get_task_status(task_id):
    """Get the status of a background task.
    ---
    get:
      summary: Get background task status
      security:
        - BearerAuth: []
      parameters:
        - in: path
          name: task_id
          required: true
          schema:
            type: string
      responses:
        200:
          description: Task status
          content:
            application/json:
              schema:
                type: object
                properties:
                  task_id:
                    type: string
                  status:
                    type: string
                    enum: [PENDING, STARTED, SUCCESS, FAILURE, RETRY, REVOKED]
                  result:
                    type: object
        503:
          description: Celery is not enabled
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    """
    if not current_app.config.get("CELERY_ENABLED"):
        return error_response("Background task queue is not enabled", status_code=503)

    from ..celery_app import celery
    result = celery.AsyncResult(task_id)
    payload = {
        "task_id": task_id,
        "status": result.status,
    }
    if result.ready():
        payload["result"] = result.result if isinstance(result.result, dict) else {"detail": str(result.result)}
    return jsonify(payload)
