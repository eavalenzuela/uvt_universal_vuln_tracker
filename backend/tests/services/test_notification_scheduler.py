from datetime import datetime, timedelta

from backend.auth import create_user
from backend.database import db
from backend.models import NotificationDeliveryCheckpoint, NotificationRule, Vulnerability
from backend.services.notification_rules import run_scheduled_notification_scan


def _seed_admin():
    admin = create_user("admin_sched", "admin_sched@example.com", "secret", role="Admin")
    db.session.flush()
    return admin


def _rule(admin_id: int, **overrides):
    data = {
        "name": "scheduled",
        "delivery_adapter": "email",
        "delivery_config": {},
        "severity_threshold": "Medium",
        "notify_on_status_change": True,
        "notify_on_assignment_change": True,
        "frequency_days": 3,
        "escalation_after_days": 5,
        "channels": ["base-channel"],
        "recipients": ["owner@example.com"],
        "created_by": admin_id,
        "is_enabled": True,
    }
    data.update(overrides)
    row = NotificationRule(**data)
    db.session.add(row)
    db.session.flush()
    return row


def _vuln(**overrides):
    data = {
        "title": "Sched Vuln",
        "severity": "High",
        "status": "Open",
    }
    data.update(overrides)
    row = Vulnerability(**data)
    db.session.add(row)
    db.session.flush()
    return row


def test_scheduled_scan_only_overdue_or_high_risk_items_trigger(app):
    with app.app_context():
        admin = _seed_admin()
        _rule(admin.id, severity_threshold="Low")

        now = datetime.utcnow()
        overdue_medium = _vuln(title="Overdue medium", severity="Medium", sla_due_at=now - timedelta(days=1))
        high_not_overdue = _vuln(title="High not overdue", severity="High", sla_due_at=now + timedelta(days=2))
        low_not_overdue = _vuln(title="Low not overdue", severity="Low", sla_due_at=now + timedelta(days=2))

        logs = run_scheduled_notification_scan(now=now, dry_run=True)
        db.session.commit()

        vuln_ids = {log.vulnerability_id for log in logs}
        assert overdue_medium.id in vuln_ids
        assert high_not_overdue.id in vuln_ids
        assert low_not_overdue.id not in vuln_ids


def test_scheduled_scan_suppresses_duplicate_reminders_within_frequency(app):
    with app.app_context():
        admin = _seed_admin()
        rule = _rule(admin.id, frequency_days=4)
        vuln = _vuln(sla_due_at=datetime.utcnow() - timedelta(days=3))

        now = datetime.utcnow()
        first_logs = run_scheduled_notification_scan(now=now, dry_run=True)
        db.session.commit()
        assert len(first_logs) == 1

        second_logs = run_scheduled_notification_scan(now=now + timedelta(days=2), dry_run=True)
        db.session.commit()
        assert len(second_logs) == 0

        checkpoint = NotificationDeliveryCheckpoint.query.filter_by(rule_id=rule.id, vulnerability_id=vuln.id).first()
        assert checkpoint is not None


def test_scheduled_scan_escalation_updates_targets(app):
    with app.app_context():
        admin = _seed_admin()
        _rule(
            admin.id,
            escalation_after_days=2,
            delivery_config={
                "escalation": {
                    "channels": ["exec-channel"],
                    "recipients": ["execs@example.com"],
                }
            },
        )
        _vuln(sla_due_at=datetime.utcnow() - timedelta(days=5), severity="Critical")

        logs = run_scheduled_notification_scan(now=datetime.utcnow(), dry_run=True)
        db.session.commit()

        assert len(logs) == 1
        payload = logs[0].response_payload
        assert payload["event_context"]["channels"] == ["exec-channel"]
        assert payload["event_context"]["recipients"] == ["execs@example.com"]

        checkpoint = NotificationDeliveryCheckpoint.query.first()
        assert checkpoint.last_escalation_step >= 1
        assert checkpoint.last_event_type == "scheduled_scan"
