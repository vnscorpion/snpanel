"""move generated panel user emails to the RFC 2606 .invalid TLD

Revision ID: 0007_panel_user_email_invalid_tld
Revises: 0006_backup_schedule_user_sets
Create Date: 2026-05-26
"""
from typing import Sequence, Union

from alembic import op


revision: str = "0007_panel_user_email_invalid_tld"
down_revision: Union[str, None] = "0006_backup_schedule_user_sets"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # @users.snpanel.vn / @users.snpanel.test were synthetic addresses for
    # auto-created panel-only users; snpanel.vn is a real domain and snpanel.test
    # is reserved but ambiguous. Move every synthetic address to the reserved
    # .invalid TLD (RFC 2606) so it can never accidentally route mail.
    op.execute(
        "UPDATE users SET email = REPLACE(email, '@users.snpanel.vn', '@users.snpanel.invalid') "
        "WHERE email LIKE '%@users.snpanel.vn'"
    )
    op.execute(
        "UPDATE users SET email = REPLACE(email, '@users.snpanel.test', '@users.snpanel.invalid') "
        "WHERE email LIKE '%@users.snpanel.test'"
    )


def downgrade() -> None:
    op.execute(
        "UPDATE users SET email = REPLACE(email, '@users.snpanel.invalid', '@users.snpanel.vn') "
        "WHERE email LIKE '%@users.snpanel.invalid'"
    )
