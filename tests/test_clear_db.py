from datetime import datetime

from sqlalchemy import inspect

from db_tools import clear_database
from models import db, User, Paper, AuditLog


def test_clear_database_preserves_tables_and_removes_rows(app):
    with app.app_context():
        admin = User(
            username='admin1',
            email='admin1@example.com',
            password_hash='hash',
            role='admin',
            public_key='public',
            private_key='private',
        )
        center = User(
            username='center1',
            email='center1@example.com',
            password_hash='hash',
            role='center',
            public_key='public',
        )
        db.session.add_all([admin, center])
        db.session.flush()
        paper = Paper(
            center_id=center.id,
            release_time=datetime(2026, 5, 5, 0, 0, 0),
            filename='sample.pdf',
            file_path='sample.enc',
            wrapped_aes_key=b'key',
            signature=b'signature',
        )
        db.session.add(paper)
        db.session.add(AuditLog(user_id=admin.id, action='login', details='test'))
        db.session.commit()

        clear_database(include_users=True)

        assert db.session.query(User).count() == 0
        assert db.session.query(Paper).count() == 0
        assert db.session.query(AuditLog).count() == 0

        table_names = set(inspect(db.engine).get_table_names())
        assert {'users', 'papers', 'audit_logs'}.issubset(table_names)
