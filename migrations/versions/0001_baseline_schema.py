"""Baseline schema.

Squashed starting point for UVT's migration history. Everything the models
described as of v2.24.0 is created here in one revision; there is no attempt to
reconstruct the releases that came before, because until now the schema was
built by ``db.create_all()`` and no revision history ever existed.

Existing installations were recreated at this point. Every schema change from
here on ships as its own revision, and ``backend/tests/test_migrations.py``
fails the build if a model changes without one.

Revision ID: 0001
Revises:
Create Date: 2026-08-04
"""
from alembic import op
import sqlalchemy as sa
import backend.database

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('attack_vectors',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('attack_vectors', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_attack_vectors_name'), ['name'], unique=True)

    op.create_table('controls',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('framework', sa.String(length=255), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('controls', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_controls_framework'), ['framework'], unique=False)
        batch_op.create_index(batch_op.f('ix_controls_name'), ['name'], unique=False)

    op.create_table('external_source_states',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('plugin_id', sa.String(length=255), nullable=False),
    sa.Column('source_key', sa.String(length=255), nullable=False),
    sa.Column('last_cursor', sa.Text(), nullable=True),
    sa.Column('last_sync_at', backend.database.TZDateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('plugin_id', 'source_key', name='unique_external_source_state')
    )
    with op.batch_alter_table('external_source_states', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_external_source_states_plugin_id'), ['plugin_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_external_source_states_source_key'), ['source_key'], unique=False)

    op.create_table('organization_branding',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('primary_color', sa.String(length=7), nullable=False),
    sa.Column('footer_text', sa.String(length=255), nullable=False),
    sa.Column('logo_path', sa.String(length=1024), nullable=True),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('teams',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('slug', sa.String(length=64), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('is_default', sa.Boolean(), nullable=False),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('teams', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_teams_is_default'), ['is_default'], unique=False)
        batch_op.create_index(batch_op.f('ix_teams_slug'), ['slug'], unique=True)

    op.create_table('terminal_impacts',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('terminal_impacts', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_terminal_impacts_name'), ['name'], unique=True)

    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=100), nullable=False),
    sa.Column('email', sa.String(length=255), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('first_name', sa.String(length=100), nullable=True),
    sa.Column('last_name', sa.String(length=100), nullable=True),
    sa.Column('role', sa.String(length=20), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('email_verified', sa.Boolean(), nullable=False),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('token_version', sa.Integer(), nullable=False),
    sa.Column('last_revoked_at', backend.database.TZDateTime(), nullable=True),
    sa.Column('failed_login_count', sa.Integer(), nullable=False),
    sa.Column('locked_until', backend.database.TZDateTime(), nullable=True),
    sa.Column('last_failed_login_at', backend.database.TZDateTime(), nullable=True),
    sa.Column('mfa_enabled', sa.Boolean(), nullable=False),
    sa.Column('mfa_secret', sa.String(length=64), nullable=True),
    sa.Column('mfa_recovery_codes', sa.JSON(), nullable=False),
    sa.Column('mfa_enrolled_at', backend.database.TZDateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_users_email'), ['email'], unique=True)
        batch_op.create_index(batch_op.f('ix_users_username'), ['username'], unique=True)

    op.create_table('api_tokens',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('secret_hash', sa.String(length=128), nullable=False),
    sa.Column('scopes', sa.JSON(), nullable=False),
    sa.Column('expires_at', backend.database.TZDateTime(), nullable=True),
    sa.Column('last_used_at', backend.database.TZDateTime(), nullable=True),
    sa.Column('revoked_at', backend.database.TZDateTime(), nullable=True),
    sa.Column('owner_id', sa.Integer(), nullable=False),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('api_tokens', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_api_tokens_expires_at'), ['expires_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_api_tokens_owner_id'), ['owner_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_api_tokens_secret_hash'), ['secret_hash'], unique=True)

    op.create_table('audit_logs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('action', sa.String(length=100), nullable=True),
    sa.Column('table_name', sa.String(length=100), nullable=True),
    sa.Column('record_id', sa.Integer(), nullable=True),
    sa.Column('team_id', sa.Integer(), nullable=True),
    sa.Column('old_values', sa.JSON(), nullable=True),
    sa.Column('new_values', sa.JSON(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_audit_logs_team_id'), ['team_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_logs_user_id'), ['user_id'], unique=False)

    op.create_table('control_sources',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('control_id', sa.Integer(), nullable=False),
    sa.Column('source', sa.String(length=100), nullable=False),
    sa.Column('source_control_id', sa.String(length=200), nullable=True),
    sa.Column('version', sa.String(length=100), nullable=True),
    sa.Column('source_url', sa.Text(), nullable=True),
    sa.Column('raw_json', sa.JSON(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['control_id'], ['controls.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('control_id', 'source', 'source_control_id', 'version', name='unique_control_source')
    )
    with op.batch_alter_table('control_sources', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_control_sources_control_id'), ['control_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_control_sources_source'), ['source'], unique=False)
        batch_op.create_index(batch_op.f('ix_control_sources_source_control_id'), ['source_control_id'], unique=False)

    op.create_table('dashboard_layout_presets',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('widget_config_json', sa.JSON(), nullable=False),
    sa.Column('visibility', sa.String(length=20), nullable=False),
    sa.Column('is_default', sa.Boolean(), nullable=False),
    sa.Column('owner_id', sa.Integer(), nullable=False),
    sa.Column('team_id', sa.Integer(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.CheckConstraint("visibility IN ('private', 'team')", name='ck_dashboard_layout_presets_visibility'),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('owner_id', 'name', name='unique_dashboard_layout_preset_owner_name')
    )
    with op.batch_alter_table('dashboard_layout_presets', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_dashboard_layout_presets_owner_id'), ['owner_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_dashboard_layout_presets_team_id'), ['team_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_dashboard_layout_presets_visibility'), ['visibility'], unique=False)

    op.create_table('email_verification_tokens',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('token_hash', sa.String(length=128), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('expires_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('used_at', backend.database.TZDateTime(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('email_verification_tokens', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_email_verification_tokens_token_hash'), ['token_hash'], unique=True)
        batch_op.create_index(batch_op.f('ix_email_verification_tokens_user_id'), ['user_id'], unique=False)

    op.create_table('notification_rules',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('is_enabled', sa.Boolean(), nullable=False),
    sa.Column('delivery_adapter', sa.String(length=20), nullable=False),
    sa.Column('delivery_config', sa.JSON(), nullable=True),
    sa.Column('severity_threshold', sa.String(length=20), nullable=False),
    sa.Column('notify_on_status_change', sa.Boolean(), nullable=False),
    sa.Column('notify_on_assignment_change', sa.Boolean(), nullable=False),
    sa.Column('product_scope', sa.JSON(), nullable=True),
    sa.Column('frequency_days', sa.Integer(), nullable=False),
    sa.Column('escalation_after_days', sa.Integer(), nullable=False),
    sa.Column('channels', sa.JSON(), nullable=True),
    sa.Column('recipients', sa.JSON(), nullable=True),
    sa.Column('created_by', sa.Integer(), nullable=False),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('team_id', sa.Integer(), nullable=True),
    sa.Column('include_shared', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
    sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('notification_rules', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_notification_rules_team_id'), ['team_id'], unique=False)

    op.create_table('password_reset_tokens',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('token_hash', sa.String(length=128), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('expires_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('used_at', backend.database.TZDateTime(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('password_reset_tokens', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_password_reset_tokens_token_hash'), ['token_hash'], unique=True)
        batch_op.create_index(batch_op.f('ix_password_reset_tokens_user_id'), ['user_id'], unique=False)

    op.create_table('plugin_configs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('plugin_id', sa.String(length=255), nullable=False),
    sa.Column('config_json', sa.JSON(), nullable=True),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('schedule_cron', sa.String(length=120), nullable=True),
    sa.Column('interval_minutes', sa.Integer(), nullable=True),
    sa.Column('team_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('plugin_configs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_plugin_configs_plugin_id'), ['plugin_id'], unique=True)
        batch_op.create_index(batch_op.f('ix_plugin_configs_team_id'), ['team_id'], unique=False)

    op.create_table('plugin_runs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('plugin_id', sa.String(length=255), nullable=False),
    sa.Column('started_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('finished_at', backend.database.TZDateTime(), nullable=True),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('stats_json', sa.JSON(), nullable=True),
    sa.Column('celery_task_id', sa.String(length=255), nullable=True),
    sa.Column('team_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('plugin_runs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_plugin_runs_celery_task_id'), ['celery_task_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_plugin_runs_plugin_id'), ['plugin_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_plugin_runs_team_id'), ['team_id'], unique=False)

    op.create_table('products',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('team_id', sa.Integer(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('created_by', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
    sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('products', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_products_name'), ['name'], unique=False)
        batch_op.create_index(batch_op.f('ix_products_team_id'), ['team_id'], unique=False)

    op.create_table('refresh_tokens',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('token_hash', sa.String(length=128), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('expires_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('revoked', sa.Boolean(), nullable=False),
    sa.Column('revoked_at', backend.database.TZDateTime(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('refresh_tokens', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_refresh_tokens_expires_at'), ['expires_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_refresh_tokens_revoked'), ['revoked'], unique=False)
        batch_op.create_index(batch_op.f('ix_refresh_tokens_token_hash'), ['token_hash'], unique=True)
        batch_op.create_index(batch_op.f('ix_refresh_tokens_user_id'), ['user_id'], unique=False)

    op.create_table('report_artifacts',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('report_type', sa.String(length=30), nullable=False),
    sa.Column('format', sa.String(length=10), nullable=False),
    sa.Column('storage_path', sa.String(length=1024), nullable=True),
    sa.Column('checksum', sa.String(length=256), nullable=True),
    sa.Column('size', sa.BigInteger(), nullable=True),
    sa.Column('content_type', sa.String(length=255), nullable=True),
    sa.Column('filters_json', sa.JSON(), nullable=True),
    sa.Column('created_by', sa.Integer(), nullable=False),
    sa.Column('team_id', sa.Integer(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('celery_task_id', sa.String(length=64), nullable=True),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
    sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('report_artifacts', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_report_artifacts_created_by'), ['created_by'], unique=False)
        batch_op.create_index(batch_op.f('ix_report_artifacts_report_type'), ['report_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_report_artifacts_status'), ['status'], unique=False)
        batch_op.create_index(batch_op.f('ix_report_artifacts_team_id'), ['team_id'], unique=False)

    op.create_table('report_templates',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('report_type', sa.String(length=30), nullable=False),
    sa.Column('fields_json', sa.JSON(), nullable=False),
    sa.Column('filters_json', sa.JSON(), nullable=False),
    sa.Column('export_format', sa.String(length=10), nullable=False),
    sa.Column('delivery_channel', sa.String(length=20), nullable=False),
    sa.Column('recipients_json', sa.JSON(), nullable=False),
    sa.Column('delivery_preferences_json', sa.JSON(), nullable=False),
    sa.Column('visibility', sa.String(length=20), nullable=False),
    sa.Column('owner_id', sa.Integer(), nullable=False),
    sa.Column('team_id', sa.Integer(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.CheckConstraint("visibility IN ('private', 'team')", name='ck_report_templates_visibility'),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('owner_id', 'name', name='unique_report_template_owner_name')
    )
    with op.batch_alter_table('report_templates', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_report_templates_owner_id'), ['owner_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_report_templates_team_id'), ['team_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_report_templates_visibility'), ['visibility'], unique=False)

    op.create_table('saved_vulnerability_filters',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('filter_json', sa.JSON(), nullable=False),
    sa.Column('visibility', sa.String(length=20), nullable=False),
    sa.Column('is_default', sa.Boolean(), nullable=False),
    sa.Column('owner_id', sa.Integer(), nullable=False),
    sa.Column('team_id', sa.Integer(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('saved_vulnerability_filters', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_saved_vulnerability_filters_owner_id'), ['owner_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_saved_vulnerability_filters_team_id'), ['team_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_saved_vulnerability_filters_visibility'), ['visibility'], unique=False)

    op.create_table('sla_policies',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('policy_json', sa.JSON(), nullable=False),
    sa.Column('updated_by', sa.Integer(), nullable=False),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['updated_by'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user_teams',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('team_id', sa.Integer(), nullable=False),
    sa.Column('role_in_team', sa.String(length=20), nullable=True),
    sa.Column('is_default', sa.Boolean(), nullable=False),
    sa.Column('joined_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('user_id', 'team_id', name='unique_user_team')
    )
    with op.batch_alter_table('user_teams', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_user_teams_is_default'), ['is_default'], unique=False)
        batch_op.create_index(batch_op.f('ix_user_teams_team_id'), ['team_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_user_teams_user_id'), ['user_id'], unique=False)

    op.create_table('vulnerabilities',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('cve_id', sa.String(length=20), nullable=True),
    sa.Column('title', sa.String(length=500), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('severity', sa.String(length=20), nullable=False),
    sa.Column('cvss_score', sa.Numeric(precision=3, scale=1), nullable=True),
    sa.Column('cvss_vector', sa.String(length=255), nullable=True),
    sa.Column('cvss_version', sa.String(length=16), nullable=True),
    sa.Column('cwe_id', sa.String(length=32), nullable=True),
    sa.Column('references_json', sa.JSON(), nullable=False),
    sa.Column('known_exploited', sa.Boolean(), nullable=False),
    sa.Column('kev_date_added', sa.Date(), nullable=True),
    sa.Column('attack_complexity', sa.String(length=20), nullable=False),
    sa.Column('confidentiality_impact', sa.String(length=20), nullable=False),
    sa.Column('integrity_impact', sa.String(length=20), nullable=False),
    sa.Column('availability_impact', sa.String(length=20), nullable=False),
    sa.Column('published_date', sa.Date(), nullable=True),
    sa.Column('last_modified_date', sa.Date(), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('sla_due_at', backend.database.TZDateTime(), nullable=True),
    sa.Column('resolved_at', backend.database.TZDateTime(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('is_merged', sa.Boolean(), nullable=False),
    sa.Column('merged_into_id', sa.Integer(), nullable=True),
    sa.Column('merge_metadata_json', sa.JSON(), nullable=False),
    sa.Column('team_id', sa.Integer(), nullable=True),
    sa.Column('created_by', sa.Integer(), nullable=True),
    sa.Column('assigned_to', sa.Integer(), nullable=True),
    sa.CheckConstraint("severity IN ('Critical', 'High', 'Medium', 'Low', 'None')", name='ck_vulnerabilities_severity'),
    sa.CheckConstraint("status IN ('Open', 'In Progress', 'Resolved', 'Closed')", name='ck_vulnerabilities_status'),
    sa.CheckConstraint('cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)', name='ck_vulnerabilities_cvss_score'),
    sa.ForeignKeyConstraint(['assigned_to'], ['users.id'], ),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
    sa.ForeignKeyConstraint(['merged_into_id'], ['vulnerabilities.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_vulnerabilities_assigned_to'), ['assigned_to'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_created_by'), ['created_by'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_cve_id'), ['cve_id'], unique=True)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_cwe_id'), ['cwe_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_is_merged'), ['is_merged'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_known_exploited'), ['known_exploited'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_merged_into_id'), ['merged_into_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_severity'), ['severity'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_status'), ['status'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_team_id'), ['team_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_title'), ['title'], unique=False)

    op.create_table('notification_delivery_checkpoints',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('rule_id', sa.Integer(), nullable=False),
    sa.Column('vulnerability_id', sa.Integer(), nullable=False),
    sa.Column('last_notified_at', backend.database.TZDateTime(), nullable=True),
    sa.Column('last_escalation_step', sa.Integer(), nullable=False),
    sa.Column('last_event_type', sa.String(length=50), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['rule_id'], ['notification_rules.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('rule_id', 'vulnerability_id', name='unique_notification_delivery_checkpoint')
    )
    with op.batch_alter_table('notification_delivery_checkpoints', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_notification_delivery_checkpoints_rule_id'), ['rule_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_notification_delivery_checkpoints_vulnerability_id'), ['vulnerability_id'], unique=False)

    op.create_table('notification_delivery_logs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('rule_id', sa.Integer(), nullable=True),
    sa.Column('vulnerability_id', sa.Integer(), nullable=True),
    sa.Column('event_type', sa.String(length=50), nullable=False),
    sa.Column('delivery_adapter', sa.String(length=20), nullable=False),
    sa.Column('success', sa.Boolean(), nullable=False),
    sa.Column('response_payload', sa.JSON(), nullable=True),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['rule_id'], ['notification_rules.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('notification_delivery_logs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_notification_delivery_logs_rule_id'), ['rule_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_notification_delivery_logs_vulnerability_id'), ['vulnerability_id'], unique=False)

    op.create_table('notifications',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('vulnerability_id', sa.Integer(), nullable=True),
    sa.Column('message', sa.Text(), nullable=False),
    sa.Column('is_read', sa.Boolean(), nullable=False),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('notifications', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_notifications_user_id'), ['user_id'], unique=False)

    op.create_table('plugin_run_artifacts',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('plugin_run_id', sa.Integer(), nullable=False),
    sa.Column('artifact_type', sa.String(length=100), nullable=False),
    sa.Column('storage_path', sa.String(length=1024), nullable=False),
    sa.Column('checksum', sa.String(length=256), nullable=True),
    sa.Column('size', sa.BigInteger(), nullable=True),
    sa.Column('content_type', sa.String(length=255), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['plugin_run_id'], ['plugin_runs.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('plugin_run_artifacts', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_plugin_run_artifacts_artifact_type'), ['artifact_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_plugin_run_artifacts_plugin_run_id'), ['plugin_run_id'], unique=False)

    op.create_table('product_controls',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('product_id', sa.Integer(), nullable=False),
    sa.Column('control_id', sa.Integer(), nullable=False),
    sa.Column('implementation_status', sa.String(length=50), nullable=False),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['control_id'], ['controls.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['product_id'], ['products.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('product_id', 'control_id', name='unique_product_control')
    )
    with op.batch_alter_table('product_controls', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_product_controls_control_id'), ['control_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_product_controls_product_id'), ['product_id'], unique=False)

    op.create_table('product_owners',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('product_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['product_id'], ['products.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('product_id', 'user_id', name='unique_product_owner')
    )
    with op.batch_alter_table('product_owners', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_product_owners_product_id'), ['product_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_product_owners_user_id'), ['user_id'], unique=False)

    op.create_table('product_versions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('product_id', sa.Integer(), nullable=False),
    sa.Column('version', sa.String(length=50), nullable=False),
    sa.Column('release_date', sa.Date(), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['product_id'], ['products.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('product_id', 'version', name='unique_product_version')
    )
    with op.batch_alter_table('product_versions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_product_versions_product_id'), ['product_id'], unique=False)

    op.create_table('report_schedules',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('report_type', sa.String(length=30), nullable=False),
    sa.Column('frequency', sa.String(length=20), nullable=False),
    sa.Column('delivery_channel', sa.String(length=20), nullable=False),
    sa.Column('recipient', sa.String(length=255), nullable=False),
    sa.Column('recipients_json', sa.JSON(), nullable=False),
    sa.Column('timezone', sa.String(length=64), nullable=False),
    sa.Column('filter_preset', sa.String(length=120), nullable=True),
    sa.Column('filters_json', sa.JSON(), nullable=True),
    sa.Column('delivery_preferences_json', sa.JSON(), nullable=False),
    sa.Column('report_template_id', sa.Integer(), nullable=True),
    sa.Column('created_by', sa.Integer(), nullable=False),
    sa.Column('team_id', sa.Integer(), nullable=True),
    sa.Column('last_run_at', backend.database.TZDateTime(), nullable=True),
    sa.Column('last_run_status', sa.String(length=30), nullable=False),
    sa.Column('last_failure_reason', sa.Text(), nullable=True),
    sa.Column('last_attempted_at', backend.database.TZDateTime(), nullable=True),
    sa.Column('retry_count', sa.Integer(), nullable=False),
    sa.Column('next_retry_at', backend.database.TZDateTime(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
    sa.ForeignKeyConstraint(['report_template_id'], ['report_templates.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('report_schedules', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_report_schedules_report_template_id'), ['report_template_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_report_schedules_team_id'), ['team_id'], unique=False)

    op.create_table('user_preferences',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('timezone', sa.String(length=64), nullable=False),
    sa.Column('theme', sa.String(length=16), nullable=False),
    sa.Column('language', sa.String(length=8), nullable=False),
    sa.Column('default_vuln_filter_id', sa.Integer(), nullable=True),
    sa.Column('default_dashboard_preset_id', sa.Integer(), nullable=True),
    sa.Column('notify_on_mention', sa.Boolean(), nullable=False),
    sa.Column('notify_on_assignment', sa.Boolean(), nullable=False),
    sa.Column('notify_on_watched_vuln_update', sa.Boolean(), nullable=False),
    sa.Column('notify_on_sla_breach', sa.Boolean(), nullable=False),
    sa.Column('email_digest_frequency', sa.String(length=16), nullable=False),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.CheckConstraint("email_digest_frequency IN ('off', 'daily', 'weekly')", name='ck_user_preferences_email_digest_frequency'),
    sa.CheckConstraint("theme IN ('auto', 'light', 'dark')", name='ck_user_preferences_theme'),
    sa.ForeignKeyConstraint(['default_dashboard_preset_id'], ['dashboard_layout_presets.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['default_vuln_filter_id'], ['saved_vulnerability_filters.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('user_preferences', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_user_preferences_default_dashboard_preset_id'), ['default_dashboard_preset_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_user_preferences_default_vuln_filter_id'), ['default_vuln_filter_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_user_preferences_user_id'), ['user_id'], unique=True)

    op.create_table('vulnerability_comments',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('vulnerability_id', sa.Integer(), nullable=False),
    sa.Column('author_id', sa.Integer(), nullable=False),
    sa.Column('body', sa.Text(), nullable=False),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_by', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['author_id'], ['users.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['updated_by'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('vulnerability_comments', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_vulnerability_comments_author_id'), ['author_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerability_comments_updated_by'), ['updated_by'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerability_comments_vulnerability_id'), ['vulnerability_id'], unique=False)

    op.create_table('vulnerability_sources',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('vulnerability_id', sa.Integer(), nullable=False),
    sa.Column('source', sa.String(length=100), nullable=False),
    sa.Column('source_id', sa.String(length=200), nullable=True),
    sa.Column('raw_json', sa.JSON(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('vulnerability_id', 'source', 'source_id', name='unique_vuln_source')
    )
    with op.batch_alter_table('vulnerability_sources', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_vulnerability_sources_source'), ['source'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerability_sources_source_id'), ['source_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerability_sources_vulnerability_id'), ['vulnerability_id'], unique=False)

    op.create_table('vulnerability_terminal_impacts',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('vulnerability_id', sa.Integer(), nullable=False),
    sa.Column('terminal_impact_id', sa.Integer(), nullable=False),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['terminal_impact_id'], ['terminal_impacts.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('vulnerability_id', 'terminal_impact_id', name='unique_vuln_terminal_impact')
    )
    with op.batch_alter_table('vulnerability_terminal_impacts', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_vulnerability_terminal_impacts_terminal_impact_id'), ['terminal_impact_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerability_terminal_impacts_vulnerability_id'), ['vulnerability_id'], unique=False)

    op.create_table('vulnerability_watchers',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('vulnerability_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('added_by', sa.Integer(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['added_by'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('vulnerability_id', 'user_id', name='unique_vulnerability_watcher')
    )
    with op.batch_alter_table('vulnerability_watchers', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_vulnerability_watchers_added_by'), ['added_by'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerability_watchers_user_id'), ['user_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerability_watchers_vulnerability_id'), ['vulnerability_id'], unique=False)

    op.create_table('plugin_run_artifact_links',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('artifact_id', sa.Integer(), nullable=False),
    sa.Column('vulnerability_id', sa.Integer(), nullable=True),
    sa.Column('product_version_id', sa.Integer(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.CheckConstraint('vulnerability_id IS NOT NULL OR product_version_id IS NOT NULL', name='ck_plugin_run_artifact_links_has_target'),
    sa.ForeignKeyConstraint(['artifact_id'], ['plugin_run_artifacts.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['product_version_id'], ['product_versions.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('artifact_id', 'vulnerability_id', 'product_version_id', name='unique_plugin_run_artifact_link')
    )
    with op.batch_alter_table('plugin_run_artifact_links', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_plugin_run_artifact_links_artifact_id'), ['artifact_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_plugin_run_artifact_links_product_version_id'), ['product_version_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_plugin_run_artifact_links_vulnerability_id'), ['vulnerability_id'], unique=False)

    op.create_table('software_components',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('product_version_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('version', sa.String(length=120), nullable=True),
    sa.Column('ecosystem', sa.String(length=80), nullable=True),
    sa.Column('purl', sa.String(length=500), nullable=True),
    sa.Column('cpe', sa.String(length=500), nullable=True),
    sa.Column('bom_ref', sa.String(length=500), nullable=True),
    sa.Column('component_type', sa.String(length=80), nullable=False),
    sa.Column('metadata_json', sa.JSON(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['product_version_id'], ['product_versions.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('product_version_id', 'bom_ref', name='unique_component_bom_ref')
    )
    with op.batch_alter_table('software_components', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_software_components_bom_ref'), ['bom_ref'], unique=False)
        batch_op.create_index(batch_op.f('ix_software_components_cpe'), ['cpe'], unique=False)
        batch_op.create_index(batch_op.f('ix_software_components_ecosystem'), ['ecosystem'], unique=False)
        batch_op.create_index(batch_op.f('ix_software_components_name'), ['name'], unique=False)
        batch_op.create_index(batch_op.f('ix_software_components_product_version_id'), ['product_version_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_software_components_purl'), ['purl'], unique=False)
        batch_op.create_index(batch_op.f('ix_software_components_version'), ['version'], unique=False)
        batch_op.create_index('ix_software_components_version_name', ['product_version_id', 'name'], unique=False)

    op.create_table('vulnerability_attack_vectors',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('vulnerability_id', sa.Integer(), nullable=False),
    sa.Column('attack_vector_id', sa.Integer(), nullable=False),
    sa.Column('product_version_id', sa.Integer(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['attack_vector_id'], ['attack_vectors.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['product_version_id'], ['product_versions.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('vulnerability_id', 'attack_vector_id', 'product_version_id', name='unique_vuln_attack_vector')
    )
    with op.batch_alter_table('vulnerability_attack_vectors', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_vulnerability_attack_vectors_attack_vector_id'), ['attack_vector_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerability_attack_vectors_product_version_id'), ['product_version_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerability_attack_vectors_vulnerability_id'), ['vulnerability_id'], unique=False)

    op.create_table('vulnerability_versions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('vulnerability_id', sa.Integer(), nullable=False),
    sa.Column('product_version_id', sa.Integer(), nullable=False),
    sa.Column('affected', sa.Boolean(), nullable=False),
    sa.Column('fixed_in_version', sa.String(length=50), nullable=True),
    sa.Column('mitigation_status', sa.String(length=30), nullable=False),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['product_version_id'], ['product_versions.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('vulnerability_id', 'product_version_id', name='unique_vuln_version')
    )
    with op.batch_alter_table('vulnerability_versions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_vulnerability_versions_product_version_id'), ['product_version_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerability_versions_vulnerability_id'), ['vulnerability_id'], unique=False)

    op.create_table('webhook_endpoints',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('source_type', sa.String(length=40), nullable=False),
    sa.Column('secret_hash', sa.String(length=128), nullable=False),
    sa.Column('is_enabled', sa.Boolean(), nullable=False),
    sa.Column('product_version_id', sa.Integer(), nullable=True),
    sa.Column('owner_id', sa.Integer(), nullable=True),
    sa.Column('team_id', sa.Integer(), nullable=True),
    sa.Column('last_delivery_at', backend.database.TZDateTime(), nullable=True),
    sa.Column('delivery_count', sa.Integer(), nullable=False),
    sa.Column('failure_count', sa.Integer(), nullable=False),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.CheckConstraint("source_type IN ('generic', 'github', 'dependabot', 'trivy', 'nessus', 'qualys')", name='ck_webhook_endpoints_source_type'),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['product_version_id'], ['product_versions.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('webhook_endpoints', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_webhook_endpoints_is_enabled'), ['is_enabled'], unique=False)
        batch_op.create_index(batch_op.f('ix_webhook_endpoints_owner_id'), ['owner_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_webhook_endpoints_product_version_id'), ['product_version_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_webhook_endpoints_secret_hash'), ['secret_hash'], unique=True)
        batch_op.create_index(batch_op.f('ix_webhook_endpoints_source_type'), ['source_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_webhook_endpoints_team_id'), ['team_id'], unique=False)

    op.create_table('component_dependencies',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('product_version_id', sa.Integer(), nullable=False),
    sa.Column('parent_component_id', sa.Integer(), nullable=False),
    sa.Column('child_component_id', sa.Integer(), nullable=False),
    sa.Column('dependency_path', sa.Text(), nullable=True),
    sa.Column('depth', sa.Integer(), nullable=False),
    sa.Column('is_direct', sa.Boolean(), nullable=False),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['child_component_id'], ['software_components.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['parent_component_id'], ['software_components.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['product_version_id'], ['product_versions.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('product_version_id', 'parent_component_id', 'child_component_id', name='unique_component_dependency')
    )
    with op.batch_alter_table('component_dependencies', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_component_dependencies_child_component_id'), ['child_component_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_component_dependencies_parent_component_id'), ['parent_component_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_component_dependencies_product_version_id'), ['product_version_id'], unique=False)

    op.create_table('vulnerability_components',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('vulnerability_id', sa.Integer(), nullable=False),
    sa.Column('component_id', sa.Integer(), nullable=False),
    sa.Column('source', sa.String(length=100), nullable=False),
    sa.Column('match_type', sa.String(length=50), nullable=False),
    sa.Column('dependency_path', sa.Text(), nullable=True),
    sa.Column('transitive_depth', sa.Integer(), nullable=False),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['component_id'], ['software_components.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('vulnerability_id', 'component_id', 'source', name='unique_vulnerability_component')
    )
    with op.batch_alter_table('vulnerability_components', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_vulnerability_components_component_id'), ['component_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerability_components_source'), ['source'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerability_components_vulnerability_id'), ['vulnerability_id'], unique=False)

    op.create_table('webhook_delivery_logs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('endpoint_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('status_code', sa.Integer(), nullable=True),
    sa.Column('payload_bytes', sa.Integer(), nullable=True),
    sa.Column('vulnerabilities_ingested', sa.Integer(), nullable=False),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('client_ip', sa.String(length=64), nullable=True),
    sa.Column('created_at', backend.database.TZDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['endpoint_id'], ['webhook_endpoints.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('webhook_delivery_logs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_webhook_delivery_logs_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_webhook_delivery_logs_endpoint_id'), ['endpoint_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_webhook_delivery_logs_status'), ['status'], unique=False)



def downgrade():
    with op.batch_alter_table('webhook_delivery_logs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_webhook_delivery_logs_status'))
        batch_op.drop_index(batch_op.f('ix_webhook_delivery_logs_endpoint_id'))
        batch_op.drop_index(batch_op.f('ix_webhook_delivery_logs_created_at'))

    op.drop_table('webhook_delivery_logs')
    with op.batch_alter_table('vulnerability_components', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_vulnerability_components_vulnerability_id'))
        batch_op.drop_index(batch_op.f('ix_vulnerability_components_source'))
        batch_op.drop_index(batch_op.f('ix_vulnerability_components_component_id'))

    op.drop_table('vulnerability_components')
    with op.batch_alter_table('component_dependencies', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_component_dependencies_product_version_id'))
        batch_op.drop_index(batch_op.f('ix_component_dependencies_parent_component_id'))
        batch_op.drop_index(batch_op.f('ix_component_dependencies_child_component_id'))

    op.drop_table('component_dependencies')
    with op.batch_alter_table('webhook_endpoints', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_webhook_endpoints_team_id'))
        batch_op.drop_index(batch_op.f('ix_webhook_endpoints_source_type'))
        batch_op.drop_index(batch_op.f('ix_webhook_endpoints_secret_hash'))
        batch_op.drop_index(batch_op.f('ix_webhook_endpoints_product_version_id'))
        batch_op.drop_index(batch_op.f('ix_webhook_endpoints_owner_id'))
        batch_op.drop_index(batch_op.f('ix_webhook_endpoints_is_enabled'))

    op.drop_table('webhook_endpoints')
    with op.batch_alter_table('vulnerability_versions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_vulnerability_versions_vulnerability_id'))
        batch_op.drop_index(batch_op.f('ix_vulnerability_versions_product_version_id'))

    op.drop_table('vulnerability_versions')
    with op.batch_alter_table('vulnerability_attack_vectors', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_vulnerability_attack_vectors_vulnerability_id'))
        batch_op.drop_index(batch_op.f('ix_vulnerability_attack_vectors_product_version_id'))
        batch_op.drop_index(batch_op.f('ix_vulnerability_attack_vectors_attack_vector_id'))

    op.drop_table('vulnerability_attack_vectors')
    with op.batch_alter_table('software_components', schema=None) as batch_op:
        batch_op.drop_index('ix_software_components_version_name')
        batch_op.drop_index(batch_op.f('ix_software_components_version'))
        batch_op.drop_index(batch_op.f('ix_software_components_purl'))
        batch_op.drop_index(batch_op.f('ix_software_components_product_version_id'))
        batch_op.drop_index(batch_op.f('ix_software_components_name'))
        batch_op.drop_index(batch_op.f('ix_software_components_ecosystem'))
        batch_op.drop_index(batch_op.f('ix_software_components_cpe'))
        batch_op.drop_index(batch_op.f('ix_software_components_bom_ref'))

    op.drop_table('software_components')
    with op.batch_alter_table('plugin_run_artifact_links', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_plugin_run_artifact_links_vulnerability_id'))
        batch_op.drop_index(batch_op.f('ix_plugin_run_artifact_links_product_version_id'))
        batch_op.drop_index(batch_op.f('ix_plugin_run_artifact_links_artifact_id'))

    op.drop_table('plugin_run_artifact_links')
    with op.batch_alter_table('vulnerability_watchers', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_vulnerability_watchers_vulnerability_id'))
        batch_op.drop_index(batch_op.f('ix_vulnerability_watchers_user_id'))
        batch_op.drop_index(batch_op.f('ix_vulnerability_watchers_added_by'))

    op.drop_table('vulnerability_watchers')
    with op.batch_alter_table('vulnerability_terminal_impacts', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_vulnerability_terminal_impacts_vulnerability_id'))
        batch_op.drop_index(batch_op.f('ix_vulnerability_terminal_impacts_terminal_impact_id'))

    op.drop_table('vulnerability_terminal_impacts')
    with op.batch_alter_table('vulnerability_sources', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_vulnerability_sources_vulnerability_id'))
        batch_op.drop_index(batch_op.f('ix_vulnerability_sources_source_id'))
        batch_op.drop_index(batch_op.f('ix_vulnerability_sources_source'))

    op.drop_table('vulnerability_sources')
    with op.batch_alter_table('vulnerability_comments', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_vulnerability_comments_vulnerability_id'))
        batch_op.drop_index(batch_op.f('ix_vulnerability_comments_updated_by'))
        batch_op.drop_index(batch_op.f('ix_vulnerability_comments_author_id'))

    op.drop_table('vulnerability_comments')
    with op.batch_alter_table('user_preferences', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_user_preferences_user_id'))
        batch_op.drop_index(batch_op.f('ix_user_preferences_default_vuln_filter_id'))
        batch_op.drop_index(batch_op.f('ix_user_preferences_default_dashboard_preset_id'))

    op.drop_table('user_preferences')
    with op.batch_alter_table('report_schedules', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_report_schedules_team_id'))
        batch_op.drop_index(batch_op.f('ix_report_schedules_report_template_id'))

    op.drop_table('report_schedules')
    with op.batch_alter_table('product_versions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_product_versions_product_id'))

    op.drop_table('product_versions')
    with op.batch_alter_table('product_owners', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_product_owners_user_id'))
        batch_op.drop_index(batch_op.f('ix_product_owners_product_id'))

    op.drop_table('product_owners')
    with op.batch_alter_table('product_controls', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_product_controls_product_id'))
        batch_op.drop_index(batch_op.f('ix_product_controls_control_id'))

    op.drop_table('product_controls')
    with op.batch_alter_table('plugin_run_artifacts', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_plugin_run_artifacts_plugin_run_id'))
        batch_op.drop_index(batch_op.f('ix_plugin_run_artifacts_artifact_type'))

    op.drop_table('plugin_run_artifacts')
    with op.batch_alter_table('notifications', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_notifications_user_id'))

    op.drop_table('notifications')
    with op.batch_alter_table('notification_delivery_logs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_notification_delivery_logs_vulnerability_id'))
        batch_op.drop_index(batch_op.f('ix_notification_delivery_logs_rule_id'))

    op.drop_table('notification_delivery_logs')
    with op.batch_alter_table('notification_delivery_checkpoints', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_notification_delivery_checkpoints_vulnerability_id'))
        batch_op.drop_index(batch_op.f('ix_notification_delivery_checkpoints_rule_id'))

    op.drop_table('notification_delivery_checkpoints')
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_title'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_team_id'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_status'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_severity'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_merged_into_id'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_known_exploited'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_is_merged'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_cwe_id'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_cve_id'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_created_by'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_assigned_to'))

    op.drop_table('vulnerabilities')
    with op.batch_alter_table('user_teams', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_user_teams_user_id'))
        batch_op.drop_index(batch_op.f('ix_user_teams_team_id'))
        batch_op.drop_index(batch_op.f('ix_user_teams_is_default'))

    op.drop_table('user_teams')
    op.drop_table('sla_policies')
    with op.batch_alter_table('saved_vulnerability_filters', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_saved_vulnerability_filters_visibility'))
        batch_op.drop_index(batch_op.f('ix_saved_vulnerability_filters_team_id'))
        batch_op.drop_index(batch_op.f('ix_saved_vulnerability_filters_owner_id'))

    op.drop_table('saved_vulnerability_filters')
    with op.batch_alter_table('report_templates', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_report_templates_visibility'))
        batch_op.drop_index(batch_op.f('ix_report_templates_team_id'))
        batch_op.drop_index(batch_op.f('ix_report_templates_owner_id'))

    op.drop_table('report_templates')
    with op.batch_alter_table('report_artifacts', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_report_artifacts_team_id'))
        batch_op.drop_index(batch_op.f('ix_report_artifacts_status'))
        batch_op.drop_index(batch_op.f('ix_report_artifacts_report_type'))
        batch_op.drop_index(batch_op.f('ix_report_artifacts_created_by'))

    op.drop_table('report_artifacts')
    with op.batch_alter_table('refresh_tokens', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_refresh_tokens_user_id'))
        batch_op.drop_index(batch_op.f('ix_refresh_tokens_token_hash'))
        batch_op.drop_index(batch_op.f('ix_refresh_tokens_revoked'))
        batch_op.drop_index(batch_op.f('ix_refresh_tokens_expires_at'))

    op.drop_table('refresh_tokens')
    with op.batch_alter_table('products', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_products_team_id'))
        batch_op.drop_index(batch_op.f('ix_products_name'))

    op.drop_table('products')
    with op.batch_alter_table('plugin_runs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_plugin_runs_team_id'))
        batch_op.drop_index(batch_op.f('ix_plugin_runs_plugin_id'))
        batch_op.drop_index(batch_op.f('ix_plugin_runs_celery_task_id'))

    op.drop_table('plugin_runs')
    with op.batch_alter_table('plugin_configs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_plugin_configs_team_id'))
        batch_op.drop_index(batch_op.f('ix_plugin_configs_plugin_id'))

    op.drop_table('plugin_configs')
    with op.batch_alter_table('password_reset_tokens', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_password_reset_tokens_user_id'))
        batch_op.drop_index(batch_op.f('ix_password_reset_tokens_token_hash'))

    op.drop_table('password_reset_tokens')
    with op.batch_alter_table('notification_rules', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_notification_rules_team_id'))

    op.drop_table('notification_rules')
    with op.batch_alter_table('email_verification_tokens', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_email_verification_tokens_user_id'))
        batch_op.drop_index(batch_op.f('ix_email_verification_tokens_token_hash'))

    op.drop_table('email_verification_tokens')
    with op.batch_alter_table('dashboard_layout_presets', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_dashboard_layout_presets_visibility'))
        batch_op.drop_index(batch_op.f('ix_dashboard_layout_presets_team_id'))
        batch_op.drop_index(batch_op.f('ix_dashboard_layout_presets_owner_id'))

    op.drop_table('dashboard_layout_presets')
    with op.batch_alter_table('control_sources', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_control_sources_source_control_id'))
        batch_op.drop_index(batch_op.f('ix_control_sources_source'))
        batch_op.drop_index(batch_op.f('ix_control_sources_control_id'))

    op.drop_table('control_sources')
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_audit_logs_user_id'))
        batch_op.drop_index(batch_op.f('ix_audit_logs_team_id'))

    op.drop_table('audit_logs')
    with op.batch_alter_table('api_tokens', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_api_tokens_secret_hash'))
        batch_op.drop_index(batch_op.f('ix_api_tokens_owner_id'))
        batch_op.drop_index(batch_op.f('ix_api_tokens_expires_at'))

    op.drop_table('api_tokens')
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_users_username'))
        batch_op.drop_index(batch_op.f('ix_users_email'))

    op.drop_table('users')
    with op.batch_alter_table('terminal_impacts', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_terminal_impacts_name'))

    op.drop_table('terminal_impacts')
    with op.batch_alter_table('teams', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_teams_slug'))
        batch_op.drop_index(batch_op.f('ix_teams_is_default'))

    op.drop_table('teams')
    op.drop_table('organization_branding')
    with op.batch_alter_table('external_source_states', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_external_source_states_source_key'))
        batch_op.drop_index(batch_op.f('ix_external_source_states_plugin_id'))

    op.drop_table('external_source_states')
    with op.batch_alter_table('controls', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_controls_name'))
        batch_op.drop_index(batch_op.f('ix_controls_framework'))

    op.drop_table('controls')
    with op.batch_alter_table('attack_vectors', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_attack_vectors_name'))

    op.drop_table('attack_vectors')
