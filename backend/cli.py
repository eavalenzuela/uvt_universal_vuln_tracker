import click
from flask import current_app
from flask.cli import with_appcontext

from .database import db
from .models import User
from .auth import hash_password
from .plugins.runner import run_plugins
from .services.notification_rules import run_scheduled_notification_scan

def _celery_enabled():
    return current_app.config.get("CELERY_ENABLED", False)

@click.command("seed-admin")
@click.option("--username", required=True, help="Admin username")
@click.option("--email", required=True, help="Admin email")
@click.option("--password", required=True, help="Admin password")
@with_appcontext
def seed_admin(username, email, password):
    """
    Create or update an Admin user.
    Safe to run multiple times.
    """
    db.create_all()
    user = User.query.filter(
        (User.username == username) | (User.email == email)
    ).first()

    if user:
        user.username = username
        user.email = email
        user.password_hash = hash_password(password)
        user.role = "Admin"
        user.is_active = True
        action = "updated"
    else:
        user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            role="Admin",
            is_active=True,
        )
        db.session.add(user)
        action = "created"

    db.session.commit()

    click.echo(f"Admin user {action}: {username}")


@click.command("run-plugins")
@click.option("--plugin-id", help="Run a specific plugin by id.")
@click.option(
    "--include-disabled",
    is_flag=True,
    help="Include disabled plugins when running all plugins.",
)
@click.option(
    "--only-due",
    is_flag=True,
    help="Skip plugins that are not due based on interval_minutes.",
)
@with_appcontext
def run_plugins_cli(plugin_id, include_disabled, only_due):
    """
    Run enabled plugins or a specific plugin.
    Designed to be cron-friendly (runs once and exits).
    """
    registry = current_app.extensions.get("plugin_registry")
    if not registry:
        raise click.ClickException("Plugin registry is not initialized.")
    if plugin_id:
        known_ids = {plugin.plugin_id for plugin in registry.list_plugins()}
        if plugin_id not in known_ids:
            raise click.ClickException(f"No plugin registered with id '{plugin_id}'.")
    runs = run_plugins(
        registry,
        plugin_id=plugin_id,
        include_disabled=include_disabled,
        only_due=only_due,
    )
    click.echo(f"Completed {len(runs)} plugin run(s).")


@click.command("run-notification-scan")
@click.option("--dry-run", is_flag=True, help="Evaluate scheduled notification rules without external delivery.")
@with_appcontext
def run_notification_scan_cli(dry_run):
    """
    Run scheduled vulnerability notification scan once and exit.
    """
    logs = run_scheduled_notification_scan(dry_run=dry_run)
    db.session.commit()
    click.echo(f"Completed scheduled notification scan with {len(logs)} delivery attempt(s).")
