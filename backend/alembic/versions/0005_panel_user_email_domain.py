"""move generated panel user emails to a valid domain

Revision ID: 0005_panel_user_email_domain
Revises: 0004_backup_schedules
Create Date: 2026-05-26
"""
from typing import Sequence, Union

from alembic import op


revision: str = "0005_panel_user_email_domain"
down_revision: Union[str, None] = "0004_backup_schedules"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("UPDATE users SET email = REPLACE(email, '@users.snpanel.test', '@users.snpanel.vn') WHERE email LIKE '%@users.snpanel.test'")


def downgrade() -> None:
    op.execute("UPDATE users SET email = REPLACE(email, '@users.snpanel.vn', '@users.snpanel.test') WHERE email LIKE '%@users.snpanel.vn'")
