"""Git Differential Engine (Spec Section 4.2).

Operational note: the repository volume should sit on an encrypted disk
and be mirrored off-host (Spec Section 12.1) --- sanitization strips
known secret patterns, but configuration content is still sensitive.
"""
import os

from git import Repo, Actor

from app.core.config import settings


class GitConfigEngine:
    def __init__(self, base_repo_path: str | None = None):
        self.base_path = base_repo_path or settings.GIT_REPO_PATH
        if not os.path.exists(os.path.join(self.base_path, ".git")):
            os.makedirs(self.base_path, exist_ok=True)
            Repo.init(self.base_path)
        self.repo = Repo(self.base_path)
        self.author = Actor("NABS System Worker", "worker@nabs.local")

    def save_and_commit(self, hostname: str, config_content: str, trigger_source: str) -> str:
        """Writes the config to disk and commits only if it changed."""
        filename = f"{hostname}.conf"
        file_path = os.path.join(self.base_path, filename)
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                if f.read().strip() == config_content.strip():
                    return ""  # No change; skip empty commit
        with open(file_path, "w") as f:
            f.write(config_content)
        self.repo.index.add([filename])
        commit = self.repo.index.commit(
            f"Backup updated via {trigger_source} for {hostname}",
            author=self.author, committer=self.author,
        )
        return commit.hexsha

    def get_history(self, hostname: str, limit: int = 20) -> list[dict]:
        """Commit history for a single device's config file.
        Boş depo (henüz hiç yedek/commit yok) [] döndürür — GitPython bu
        durumda 'refs/heads/master does not exist' fırlatır."""
        if not self.repo.head.is_valid():
            return []
        filename = f"{hostname}.conf"
        return [
            {
                "commit": c.hexsha,
                "message": c.message.strip(),
                "date": c.committed_datetime.isoformat(),
            }
            for c in self.repo.iter_commits(paths=filename, max_count=limit)
        ]

    def get_content_at_commit(self, hostname: str, commit: str) -> str:
        """Belirli bir commit'teki config içeriğini döndürür (drift golden'ı)."""
        from git.exc import GitCommandError
        filename = f"{hostname}.conf"
        try:
            return self.repo.git.show(f"{commit}:{filename}")
        except GitCommandError:
            return ""

    def get_current_content(self, hostname: str) -> str:
        """Diskteki (en son commit'lenmiş) config içeriği."""
        file_path = os.path.join(self.base_path, f"{hostname}.conf")
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                return f.read()
        return ""

    def get_latest_commit(self, hostname: str) -> str:
        """Cihaz config'inin en son commit hash'i (baseline pin'i için)."""
        if not self.repo.head.is_valid():
            return ""
        commits = list(self.repo.iter_commits(paths=f"{hostname}.conf", max_count=1))
        return commits[0].hexsha if commits else ""

    def get_diff(self, hostname: str, commit_a: str, commit_b: str) -> str:
        """Unified diff of a device config between two commits.
        Geçersiz/bilinmeyen commit'lerde ValueError üretir (endpoint 400'e çevirir)."""
        from git.exc import GitCommandError

        if not self.repo.head.is_valid():
            return ""
        filename = f"{hostname}.conf"
        try:
            return self.repo.git.diff(commit_a, commit_b, "--", filename)
        except GitCommandError as exc:
            raise ValueError(f"Geçersiz commit referansı: {exc.stderr.strip()[:200]}") from exc


_engine: GitConfigEngine | None = None


def get_git_engine() -> GitConfigEngine:
    global _engine
    if _engine is None:
        _engine = GitConfigEngine()
    return _engine
