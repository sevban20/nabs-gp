"""Small admin CLI: create the first admin user.

Usage:
    python -m app.cli create-admin <username> <password>
"""
import sys

from app.core.auth import hash_password
from app.core.database import Base, SessionLocal, engine
from app.models.models import User


def create_admin(username: str, password: str) -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == username).first():
            print(f"User '{username}' already exists.")
            return
        db.add(User(username=username, password_hash=hash_password(password), role="admin"))
        db.commit()
        print(f"Admin user '{username}' created.")
    finally:
        db.close()


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "create-admin":
        create_admin(sys.argv[2], sys.argv[3])
    else:
        print(__doc__)
