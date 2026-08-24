"""Small admin CLI.

Usage:
    python -m app.cli create-admin <username> <password>
    python -m app.cli set-mirror <git-remote-url>     # off-host config aynası
    python -m app.cli show-mirror
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


def set_mirror(url: str) -> None:
    """Config deposuna 'mirror' remote'unu ekler/günceller (Spec 12.1).

    Bu remote tanımlı değilse `mirror_git_repository` görevi 15 dakikada bir
    sessizce atlanır ve config geçmişinin host dışında kopyası olmaz.
    """
    from app.services.git_engine import get_git_engine

    repo = get_git_engine().repo
    if "mirror" in {r.name for r in repo.remotes}:
        repo.remotes.mirror.set_url(url)
        print(f"'mirror' remote guncellendi: {url}")
    else:
        repo.create_remote("mirror", url)
        print(f"'mirror' remote eklendi: {url}")


def show_mirror() -> None:
    from app.services.git_engine import get_git_engine

    repo = get_git_engine().repo
    remote = next((r for r in repo.remotes if r.name == "mirror"), None)
    if remote is None:
        print("UYARI: 'mirror' remote tanimli degil — config deposunun host disi "
              "kopyasi alinmiyor. 'python -m app.cli set-mirror <url>' ile ekleyin.")
        sys.exit(1)
    print(f"mirror -> {list(remote.urls)[0]}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "create-admin" and len(sys.argv) == 4:
        create_admin(sys.argv[2], sys.argv[3])
    elif cmd == "set-mirror" and len(sys.argv) == 3:
        set_mirror(sys.argv[2])
    elif cmd == "show-mirror" and len(sys.argv) == 2:
        show_mirror()
    else:
        print(__doc__)
