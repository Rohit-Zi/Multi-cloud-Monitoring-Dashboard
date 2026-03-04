"""add log_id to alerts and update logs table

Revision ID: 5d761bb109f3
Revises: 
Create Date: 2026-03-04 15:36:27.434590

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5d761bb109f3'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add new columns to logs table only
    op.add_column('logs', sa.Column('cloud', sa.String(), nullable=True))
    op.add_column('logs', sa.Column('provider', sa.String(), nullable=True))
    op.add_column('logs', sa.Column('event_source', sa.String(), nullable=True))
    op.add_column('logs', sa.Column('event_name', sa.String(), nullable=True))
    op.add_column('logs', sa.Column('event_category', sa.String(), nullable=True))
    op.add_column('logs', sa.Column('user', sa.String(), nullable=True))
    op.add_column('logs', sa.Column('source_ip', sa.String(), nullable=True))
    op.add_column('logs', sa.Column('region', sa.String(), nullable=True))
    op.add_column('logs', sa.Column('resource', sa.String(), nullable=True))
    op.add_column('logs', sa.Column('outcome', sa.String(), nullable=True))
    op.add_column('logs', sa.Column('error_code', sa.String(), nullable=True))
    op.add_column('logs', sa.Column('timestamp', sa.String(), nullable=True))
    op.add_column('logs', sa.Column('created_at', sa.DateTime(), nullable=True))
    op.add_column('logs', sa.Column('raw_log', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('logs', 'raw_log')
    op.drop_column('logs', 'created_at')
    op.drop_column('logs', 'timestamp')
    op.drop_column('logs', 'error_code')
    op.drop_column('logs', 'outcome')
    op.drop_column('logs', 'resource')
    op.drop_column('logs', 'region')
    op.drop_column('logs', 'source_ip')
    op.drop_column('logs', 'user')
    op.drop_column('logs', 'event_category')
    op.drop_column('logs', 'event_name')
    op.drop_column('logs', 'event_source')
    op.drop_column('logs', 'provider')
    op.drop_column('logs', 'cloud')
    # ### end Alembic commands ###
