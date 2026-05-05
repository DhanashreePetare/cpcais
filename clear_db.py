from app import create_app
from db_tools import clear_database
from models import db


if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
        clear_database(include_users=True)
    print('Database rows deleted; tables were preserved.')
