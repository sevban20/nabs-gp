"""Central configuration. Fail-closed principle (Spec Section 13.4):
secret-handling components must refuse to start when misconfigured."""
import os


class Settings:
    APP_ENV: str = os.getenv("APP_ENV", "production")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./nabs_dev.db")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
    GIT_REPO_PATH: str = os.getenv("NABS_GIT_REPO_PATH", "/var/nabs/git_repo")
    SFTPGO_UPLOAD_ROOT: str = os.getenv("SFTPGO_UPLOAD_ROOT", "/var/nabs/sftpgo_uploads")
    OLLAMA_ENDPOINT: str = os.getenv("OLLAMA_ENDPOINT", "http://localhost:11434/api/generate")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3:8b-instruct")

    @property
    def jwt_secret(self) -> str:
        from app.core.secrets import get_secret
        secret = get_secret("JWT_SECRET")
        if not secret:
            if self.APP_ENV == "development":
                return "dev-only-insecure-secret"
            raise RuntimeError(
                "JWT_SECRET is not set. Refusing to start with a default "
                "secret in non-development mode (fail closed)."
            )
        return secret


settings = Settings()
