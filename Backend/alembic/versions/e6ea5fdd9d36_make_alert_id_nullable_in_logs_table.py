"""make alert_id nullable in logs table

Revision ID: e6ea5fdd9d36
Revises: dadf07176429
Create Date: 2026-08-27 23:21:01.617784

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e6ea5fdd9d36'
down_revision: Union[str, Sequence[str], None] = 'dadf07176429'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('logs', schema=None) as batch_op:
        batch_op.alter_column(
            'alert_id',
            existing_type=sa.String(),
            nullable=True,
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('logs', schema=None) as batch_op:
        batch_op.alter_column(
            'alert_id',
            existing_type=sa.String(),
            nullable=False,
        )