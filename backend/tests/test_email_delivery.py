from types import SimpleNamespace

import pytest

from backend.services import notification_rules
from backend.services.email_delivery import EmailDeliveryError, resolve_email_config, send_email
from backend.api import reports


class _DummySMTP:
    def __init__(self, host, port, timeout):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.started_tls = False
        self.login_args = None
        self.messages = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def starttls(self):
        self.started_tls = True

    def login(self, username, password):
        self.login_args = (username, password)

    def send_message(self, msg):
        self.messages.append(msg)


def test_send_email_smtp_success(monkeypatch):
    created = {}

    def fake_smtp(host, port, timeout):
        smtp = _DummySMTP(host, port, timeout)
        created["smtp"] = smtp
        return smtp

    monkeypatch.setattr("backend.services.email_delivery.smtplib.SMTP", fake_smtp)

    result = send_email(
        recipient="ops@example.com",
        subject="Test",
        body_text="body",
        config_overrides={
            "provider": "smtp",
            "host": "smtp.example.com",
            "port": 2525,
            "sender": "noreply@example.com",
            "username": "svc",
            "password": "pw",
            "use_tls": True,
            "timeout_seconds": 3,
        },
    )

    assert result["channel"] == "email"
    assert result["provider"] == "smtp"
    assert result["recipient"] == "ops@example.com"
    assert result["transport"]["host"] == "smtp.example.com"
    assert created["smtp"].started_tls is True
    assert created["smtp"].login_args == ("svc", "pw")
    assert len(created["smtp"].messages) == 1


def test_send_email_delivery_failure_raises(monkeypatch):
    def fake_smtp(host, port, timeout):
        raise OSError("socket down")

    monkeypatch.setattr("backend.services.email_delivery.smtplib.SMTP", fake_smtp)

    with pytest.raises(EmailDeliveryError, match="Email delivery failed"):
        send_email(
            recipient="ops@example.com",
            subject="Test",
            body_text="body",
            config_overrides={"provider": "smtp", "host": "smtp.example.com", "port": 25, "sender": "noreply@example.com"},
        )


def test_resolve_email_config_validation_errors():
    with pytest.raises(EmailDeliveryError, match="Missing SMTP host"):
        resolve_email_config(overrides={"provider": "smtp", "sender": "noreply@example.com", "host": ""})

    with pytest.raises(EmailDeliveryError, match="sender"):
        resolve_email_config(overrides={"provider": "smtp", "host": "smtp.example.com", "sender": ""})

    with pytest.raises(EmailDeliveryError, match="port"):
        resolve_email_config(overrides={"provider": "smtp", "host": "smtp.example.com", "sender": "x@example.com", "port": "bad"})


def test_notification_email_send_success_and_failure(monkeypatch):
    sent = []

    def fake_send_email(**kwargs):
        sent.append(kwargs)
        return {"channel": "email", "recipient": kwargs["recipient"], "metadata": {"elapsed_ms": 1}}

    monkeypatch.setattr(notification_rules, "send_email", fake_send_email)

    ok = notification_rules._email_send(
        {"recipients": ["one@example.com", "two@example.com"]},
        {"text": "hello", "vulnerability_id": 12, "event_type": "status_change"},
    )
    assert ok["count"] == 2
    assert {d["recipient"] for d in ok["deliveries"]} == {"one@example.com", "two@example.com"}
    assert len(sent) == 2

    with pytest.raises(EmailDeliveryError, match="recipient"):
        notification_rules._email_send({}, {"text": "hello", "vulnerability_id": 12, "event_type": "status_change"})


def test_report_email_delivery_success_and_error(monkeypatch):
    schedule = SimpleNamespace(
        delivery_channel="email",
        recipient="report@example.com",
        name="Nightly",
        frequency="daily",
        report_type="vulnerabilities",
    )

    def fake_send_email(**kwargs):
        return {
            "channel": "email",
            "provider": "smtp",
            "recipient": kwargs["recipient"],
            "subject": kwargs["subject"],
            "metadata": {"elapsed_ms": 1},
        }

    monkeypatch.setattr(reports, "send_email", fake_send_email)

    ok = reports._deliver_report(schedule, "id,title\n1,test\n")
    assert ok["channel"] == "email"
    assert ok["recipient"] == "report@example.com"
    assert "Nightly" in ok["subject"]

    def fail_send_email(**kwargs):
        raise EmailDeliveryError("delivery_failed", "boom", metadata={"provider": "smtp"})

    monkeypatch.setattr(reports, "send_email", fail_send_email)
    failed = reports._deliver_report(schedule, "id,title\n1,test\n")
    assert failed["channel"] == "email"
    assert failed["error"]["code"] == "delivery_failed"
