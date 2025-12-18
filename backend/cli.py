import click
from flask.cli import with_appcontext

from .database import db
from .models import User
from .auth import hash_password

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
