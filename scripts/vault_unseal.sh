#!/usr/bin/env bash
# Vault her yeniden başlatıldığında SEALED gelir ve açılması gerekir.
# Bu script vault-init.secret'taki unseal anahtarıyla Vault'u açar.
#
# Üretimde daha iyisi: cloud KMS / transit ile OTOMATIK UNSEAL yapılandırın
# (config.hcl'e 'seal' bloğu) — böylece restart'ta manuel adım gerekmez.
set -euo pipefail

VAULT_CONTAINER="${VAULT_CONTAINER:-nabs-vault}"
OUT_FILE="${OUT_FILE:-vault-init.secret}"

if [ ! -f "$OUT_FILE" ]; then
  echo "HATA: $OUT_FILE bulunamadı (unseal anahtarı burada)." >&2
  exit 1
fi
UNSEAL_KEY=$(grep -m1 'Unseal Key 1' "$OUT_FILE" | awk '{print $NF}' || true)
if [ -z "$UNSEAL_KEY" ]; then
  echo "HATA: $OUT_FILE içinde 'Unseal Key 1' satırı yok." >&2
  exit 1
fi

if docker exec -e VAULT_ADDR=http://127.0.0.1:8200 "$VAULT_CONTAINER" vault status >/dev/null 2>&1; then
  echo "Vault zaten açık (unsealed)."
else
  docker exec -e VAULT_ADDR=http://127.0.0.1:8200 "$VAULT_CONTAINER" \
    vault operator unseal "$UNSEAL_KEY" >/dev/null
  echo "Vault açıldı (unsealed)."
fi
