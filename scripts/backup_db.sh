#!/usr/bin/env bash
# Bölüm 12.2: PostgreSQL fiziksel/mantıksal yedekleme.
# Kimlik bilgileri .env'den okunur; yedek deposunda da secret'lar uygulama
# katmanında AES-256-GCM şifreli kalır (yeni düz-metin ifşa noktası oluşmaz).
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/nabs/db_backups}"
RETENTION_DAYS="${DB_BACKUP_RETENTION_DAYS:-14}"
STAMP="$(date +%Y%m%d_%H%M%S)"

mkdir -p "$BACKUP_DIR"

docker exec nabs-postgres pg_dump -U "${POSTGRES_USER:-nabs_admin}" \
  -d "${POSTGRES_DB:-nabs_governance}" -Fc \
  > "$BACKUP_DIR/nabs_${STAMP}.dump"

# Saklama penceresi dışındakileri temizle (Bölüm 12.3 ile hizalı)
find "$BACKUP_DIR" -name 'nabs_*.dump' -mtime "+$RETENTION_DAYS" -delete

echo "Yedek alındı: $BACKUP_DIR/nabs_${STAMP}.dump (saklama: ${RETENTION_DAYS} gün)"
