"""empty message

Revision ID: 76d109d11a33
Revises: 672c9ca6ecd5
Create Date: 2020-06-07 16:43:01.306992

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '76d109d11a33'
down_revision = '672c9ca6ecd5'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index('password', table_name='user')
    op.drop_column('user', 'password')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('password', mysql.VARCHAR(length=10), nullable=False))
    op.create_index('password', 'user', ['password'], unique=True)
    # ### end Alembic commands ###