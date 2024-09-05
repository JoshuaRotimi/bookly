"""create reviews table

Revision ID: 2aa1aa32af6c
Revises: b35052370ac2
Create Date: 2024-08-30 15:47:23.203065

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '2aa1aa32af6c'
down_revision: Union[str, None] = 'b35052370ac2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('reviews',
    sa.Column('uid', sa.UUID(), nullable=False),
    sa.Column('rating', sa.Integer(), nullable=False),
    sa.Column('review_text', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
    sa.Column('user_uid', sa.Uuid(), nullable=True),
    sa.Column('book_uid', sa.Uuid(), nullable=True),
    sa.Column('created_at', postgresql.TIMESTAMP(), nullable=True),
    sa.Column('updated_at', postgresql.TIMESTAMP(), nullable=True),
    sa.ForeignKeyConstraint(['book_uid'], ['books.uid'], ),
    sa.ForeignKeyConstraint(['user_uid'], ['users.uid'], ),
    sa.PrimaryKeyConstraint('uid')
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('reviews')
    # ### end Alembic commands ###
