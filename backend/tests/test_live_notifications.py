import json
from datetime import datetime, timedelta

from backend.database import db
from backend.live_notifications import hub
from backend.models import NotificationRule, Vulnerability
from backend.services.notification_rules import (
    NotificationEvent,
    run_scheduled_notification_scan,
    trigger_mention_notifications,
    trigger_notifications_for_event,
)


def test_notification_stream_requires_auth(client):
    response = client.get("/api/notifications/stream")
    assert response.status_code == 401


def test_notification_stream_sends_sse_events(app, client, admin_user, auth_header, monkeypatch):
    def _single_event(_user_id):
        yield {"type": "rule_triggered", "payload": {"vulnerability_id": 9}}

    monkeypatch.setattr("backend.api.live_notifications.queue_generator", _single_event)

    token = auth_header(admin_user)["Authorization"].split(" ", 1)[1]
    response = client.get(f"/api/notifications/stream?token={token}")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "event: connected" in body
    assert "event: rule_triggered" in body
    assert json.dumps({"payload": {"vulnerability_id": 9}, "type": "rule_triggered"}, sort_keys=True) in body


def test_triggers_publish_live_events(app, admin_user, user_factory):
    mentioned = user_factory(username="mentioned_user")

    with app.app_context():
        vuln = Vulnerability(
            cve_id="CVE-2026-9991",
            title="Queue publish",
            severity="High",
            status="Open",
            created_by=admin_user.id,
            assigned_to=mentioned.id,
        )
        db.session.add(vuln)
        db.session.commit()

        queue = hub.subscribe(mentioned.id)

        trigger_mention_notifications(
            vulnerability_id=vuln.id,
            actor_id=admin_user.id,
            comment_id=42,
            comment_text="hello @mentioned_user",
        )
        trigger_notifications_for_event(
            NotificationEvent(
                event_type="assignment_change",
                vulnerability_id=vuln.id,
                actor_id=admin_user.id,
                assignment_changed=True,
            )
        )

        events = [queue.get(timeout=1), queue.get(timeout=1)]
        event_types = {event["type"] for event in events}
        assert "mention_notification_created" in event_types
        assert "rule_triggered" in event_types

        hub.unsubscribe(mentioned.id, queue)


def test_scheduled_scan_escalation_publishes_event(app, admin_user):
    with app.app_context():
        vuln = Vulnerability(
            cve_id="CVE-2026-9992",
            title="Escalation publish",
            severity="Critical",
            status="Open",
            created_by=admin_user.id,
            assigned_to=admin_user.id,
            sla_due_at=datetime.utcnow() - timedelta(days=10),
        )
        db.session.add(vuln)
        db.session.flush()

        rule = NotificationRule(
            name="Escalation rule",
            is_enabled=True,
            delivery_adapter="webhook",
            delivery_config={"webhook_url": "http://example.invalid/webhook"},
            severity_threshold="High",
            created_by=admin_user.id,
            escalation_after_days=1,
        )
        db.session.add(rule)
        db.session.commit()

        queue = hub.subscribe(admin_user.id)
        run_scheduled_notification_scan(now=datetime.utcnow(), dry_run=True)
        event = queue.get(timeout=1)
        assert event["type"] == "scheduled_scan_escalation_logged"
        assert event["payload"]["vulnerability_id"] == vuln.id
        hub.unsubscribe(admin_user.id, queue)
