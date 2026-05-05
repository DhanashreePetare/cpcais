from models import db, User, Paper, AuditLog


def clear_database(include_users=True):
    """Delete table rows while keeping the schema intact."""
    db.session.query(AuditLog).delete(synchronize_session=False)
    db.session.query(Paper).delete(synchronize_session=False)
    if include_users:
        db.session.query(User).delete(synchronize_session=False)
    db.session.commit()
