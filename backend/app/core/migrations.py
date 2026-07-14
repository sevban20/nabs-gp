"""Hafif başlangıç migration'ları.

Base.metadata.create_all yeni TABLOLARI oluşturur ama mevcut tablolara
yeni KOLON eklemez. Eski bir DB ile yeni kod çalıştığında (örn. users
tablosunda mfa_secret_encrypted yokken) her sorgu 500 üretir. Bu modül
bilinen kolon eklemelerini idempotent biçimde uygular. Kapsamlı şema
evrimi için üretimde Alembic önerilir.
"""
import logging

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

logger = logging.getLogger("nabs.migrations")

# (tablo, kolon, SQL tip tanımı) — hem SQLite hem Postgres'te geçerli
_COLUMN_ADDITIONS: list[tuple[str, str, str]] = [
    ("users", "mfa_secret_encrypted", "TEXT"),
    ("remediation_actions", "requested_by", "VARCHAR(128)"),
    ("assets", "is_reachable", "BOOLEAN"),
    ("assets", "last_reachability_check_at", "TIMESTAMP"),
    ("assets", "has_drift", "BOOLEAN DEFAULT FALSE"),
    ("assets", "last_drift_check_at", "TIMESTAMP"),
]

# create_all mevcut tablolara kolon eklemez ama YENİ tabloları (api_keys gibi)
# oluşturur; bu yüzden api_keys için ayrı bir ALTER gerekmez.


def run_startup_migrations(engine: Engine) -> None:
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    with engine.begin() as conn:
        for table, column, coltype in _COLUMN_ADDITIONS:
            if table not in existing_tables:
                continue  # create_all birazdan sıfırdan oluşturacak
            columns = {c["name"] for c in inspector.get_columns(table)}
            if column not in columns:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}"))
                logger.info("Migration: %s.%s eklendi", table, column)
