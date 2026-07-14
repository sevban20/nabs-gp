#!/usr/bin/env bash
# NABS-GP gömülü Vault ilk kurulumu: init + unseal + KV v2 + secret yazma + app token.
#
# ÖN KOŞUL: nabs-vault konteyneri çalışıyor olmalı:
#   docker compose -f docker-compose.yml -f docker-compose.vault.yml up -d nabs-vault
#
# ÇIKTI: unseal anahtarı ve root token 'vault-init.secret' dosyasına yazılır.
#   BU DOSYAYI GÜVENLE SAKLAYIN VE SUNUCUDAN TAŞIYIN — kaybederseniz Vault
#   verisine (ve şifreli her şeye) erişemezsiniz.
set -euo pipefail

VAULT_CONTAINER="${VAULT_CONTAINER:-nabs-vault}"
OUT_FILE="${OUT_FILE:-vault-init.secret}"
KV_PATH="${VAULT_KV_MOUNT:-secret}"
SECRET_PATH="${VAULT_SECRET_PATH:-nabs-gp}"

vx() { docker exec -e VAULT_ADDR=http://127.0.0.1:8200 "$VAULT_CONTAINER" "$@"; }

echo "==> Vault durumu kontrol ediliyor…"
if vx vault status >/dev/null 2>&1; then
  echo "Vault zaten initialize ve unsealed. (Secret yazma adımına geçiliyor.)"
  if [ ! -f "$OUT_FILE" ]; then
    echo "HATA: $OUT_FILE yok; root token olmadan devam edilemez." >&2
    exit 1
  fi
  ROOT_TOKEN=$(grep 'Root Token' "$OUT_FILE" | awk '{print $NF}')
else
  # status exit code: 2 = sealed, 1/other = uninitialized
  if vx vault status 2>&1 | grep -q 'Initialized.*true'; then
    echo "==> Vault initialize edilmiş ama sealed. Unseal ediliyor…"
    if [ ! -f "$OUT_FILE" ]; then echo "HATA: $OUT_FILE yok." >&2; exit 1; fi
    UNSEAL_KEY=$(grep 'Unseal Key 1' "$OUT_FILE" | awk '{print $NF}')
    ROOT_TOKEN=$(grep 'Root Token' "$OUT_FILE" | awk '{print $NF}')
    vx vault operator unseal "$UNSEAL_KEY" >/dev/null
  else
    echo "==> Vault initialize ediliyor (1 anahtar, eşik 1 — tek düğüm)…"
    INIT_JSON=$(vx vault operator init -key-shares=1 -key-threshold=1 -format=json)
    UNSEAL_KEY=$(echo "$INIT_JSON" | python3 -c "import sys,json;print(json.load(sys.stdin)['unseal_keys_b64'][0])")
    ROOT_TOKEN=$(echo "$INIT_JSON" | python3 -c "import sys,json;print(json.load(sys.stdin)['root_token'])")
    {
      echo "# NABS-GP Vault init $(date -u +%FT%TZ) — GÜVENLE SAKLAYIN, SUNUCUDAN TAŞIYIN"
      echo "Unseal Key 1: $UNSEAL_KEY"
      echo "Root Token: $ROOT_TOKEN"
    } > "$OUT_FILE"
    chmod 600 "$OUT_FILE"
    echo "==> Unseal ediliyor…"
    vx vault operator unseal "$UNSEAL_KEY" >/dev/null
  fi
fi

echo "==> KV v2 motoru ($KV_PATH) etkinleştiriliyor…"
vx sh -c "VAULT_TOKEN=$ROOT_TOKEN vault secrets enable -path=$KV_PATH kv-v2" 2>/dev/null \
  || echo "   (zaten etkin)"

echo "==> NABS bootstrap secret'ları yazılıyor ($KV_PATH/$SECRET_PATH)…"
# Değerleri mevcut ortamdan al; yoksa üret/uyar.
: "${NABS_MASTER_KEY:=}"
: "${JWT_SECRET:=}"
: "${SFTPGO_WEBHOOK_SECRET:=}"
if [ -z "$NABS_MASTER_KEY" ]; then
  NABS_MASTER_KEY=$(python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")
  echo "   NABS_MASTER_KEY üretildi (env'de yoktu)."
fi
[ -z "$JWT_SECRET" ] && JWT_SECRET=$(python3 -c "import secrets;print(secrets.token_urlsafe(48))")
[ -z "$SFTPGO_WEBHOOK_SECRET" ] && SFTPGO_WEBHOOK_SECRET=$(python3 -c "import secrets;print(secrets.token_urlsafe(32))")

vx sh -c "VAULT_TOKEN=$ROOT_TOKEN vault kv put $KV_PATH/$SECRET_PATH \
  NABS_MASTER_KEY='$NABS_MASTER_KEY' \
  JWT_SECRET='$JWT_SECRET' \
  SFTPGO_WEBHOOK_SECRET='$SFTPGO_WEBHOOK_SECRET'" >/dev/null

echo "==> Uygulama için sınırlı yetkili token üretiliyor (yalnızca okuma)…"
vx sh -c "VAULT_TOKEN=$ROOT_TOKEN sh -c 'echo \"path \\\"$KV_PATH/data/$SECRET_PATH\\\" { capabilities = [\\\"read\\\"] }\" | vault policy write nabs-read -'" >/dev/null
APP_TOKEN=$(vx sh -c "VAULT_TOKEN=$ROOT_TOKEN vault token create -policy=nabs-read -period=768h -format=json" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['auth']['client_token'])")
# App token'ı da güvenli dosyaya yaz (install.sh buradan okuyup .env'e ekler)
grep -q '^App Token:' "$OUT_FILE" 2>/dev/null \
  && sed -i.bak "s|^App Token:.*|App Token: $APP_TOKEN|" "$OUT_FILE" && rm -f "$OUT_FILE.bak" \
  || echo "App Token: $APP_TOKEN" >> "$OUT_FILE"

cat <<EOF

============================================================
Vault hazır. Şimdi .env dosyanıza şunları ekleyin:

  VAULT_ADDR=http://nabs-vault:8200
  VAULT_TOKEN=$APP_TOKEN
  VAULT_KV_MOUNT=$KV_PATH
  VAULT_SECRET_PATH=$SECRET_PATH

Sonra tüm stack'i başlatın:
  docker compose -f docker-compose.yml -f docker-compose.vault.yml up -d

NOT:
  * Unseal anahtarı + root token: $OUT_FILE  (GÜVENLE SAKLAYIN, SUNUCUDAN TAŞIYIN)
  * Vault her yeniden başlatıldığında UNSEAL gerekir: ./scripts/vault_unseal.sh
  * App token 32 günlük (period). Süresi dolmadan yenileyin ya da AppRole'e geçin.
============================================================
EOF
