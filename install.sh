#!/usr/bin/env bash
# ============================================================================
# NABS-GP Kurulum Sihirbazı
# Unzip sonrası çalıştırın:  ./install.sh
# Sorulara Enter ile varsayılanı kabul edebilirsiniz.
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

# ---- görsel yardımcılar ----
if [ -t 1 ]; then
  B=$(printf '\033[1m'); D=$(printf '\033[2m'); G=$(printf '\033[32m')
  Y=$(printf '\033[33m'); R=$(printf '\033[31m'); C=$(printf '\033[36m'); N=$(printf '\033[0m')
else B=""; D=""; G=""; Y=""; R=""; C=""; N=""; fi
say()  { echo "${C}==>${N} $*"; }
ok()   { echo "${G}  ✓${N} $*"; }
warn() { echo "${Y}  !${N} $*"; }
die()  { echo "${R}HATA:${N} $*" >&2; exit 1; }

ask() {  # ask "Soru" "varsayılan" -> yanıtı stdout
  local q="$1" def="${2:-}" ans
  if [ -n "$def" ]; then printf "%s ${D}[%s]${N}: " "$q" "$def" >&2
  else printf "%s: " "$q" >&2; fi
  read -r ans || true
  echo "${ans:-$def}"
}
ask_secret() {  # gizli girdi
  local q="$1" ans
  printf "%s: " "$q" >&2
  read -rs ans || true; echo >&2
  echo "$ans"
}
yesno() {  # yesno "Soru" "y|n"  -> 0=evet
  local def="${2:-y}" a
  a=$(ask "$1 (e/h)" "$def"); case "$a" in e|E|y|Y|evet|yes) return 0;; *) return 1;; esac
}
gen() { python3 - <<'PY'
import os,base64;print(base64.b64encode(os.urandom(32)).decode())
PY
}
gentok() { python3 - <<'PY'
import secrets;print(secrets.token_urlsafe(32))
PY
}

echo
echo "${B}  NABS-GP — Network Asset, Backup & Security Governance${N}"
echo "${D}  Kurulum sihirbazı${N}"
echo

# ---- 1) Önkoşullar ----
say "Önkoşullar kontrol ediliyor"
command -v docker >/dev/null 2>&1 || die "docker bulunamadı. Docker Engine 24+ kurun."
if docker compose version >/dev/null 2>&1; then DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then DC="docker-compose"
else die "docker compose (v2) bulunamadı."; fi
command -v python3 >/dev/null 2>&1 || die "python3 bulunamadı (secret üretimi için gerekli)."
docker info >/dev/null 2>&1 || die "Docker çalışmıyor ya da yetki yok (sudo/gruba ekleme gerekebilir)."
ok "docker, ${DC}, python3 mevcut"

# ---- .env zaten var mı ----
if [ -f .env ]; then
  warn ".env zaten var."
  yesno "Üzerine yazılsın mı? (Hayır → mevcut .env korunur, doğrudan kuruluma geçilir)" "h" \
    && OVERWRITE=1 || OVERWRITE=0
else OVERWRITE=1; fi

COMPOSE_FILES=(-f docker-compose.yml)
USE_VAULT=0

if [ "$OVERWRITE" = "1" ]; then
  echo; say "Yapılandırma soruları"

  # ---- 2) Alan adı / erişim ----
  DOMAIN=$(ask "GUI için alan adı (FQDN). Yalnızca yerel test için 'localhost'" "localhost")

  # ---- 3) Secret'lar ----
  if yesno "Secret'lar (master key, JWT, webhook, DB parolası) otomatik üretilsin mi?" "e"; then
    NABS_MASTER_KEY=$(gen); JWT_SECRET=$(gentok); SFTPGO_WEBHOOK_SECRET=$(gentok)
    POSTGRES_PASSWORD=$(gentok); GF_PASS=$(gentok)
    ok "Secret'lar üretildi"
  else
    NABS_MASTER_KEY=$(ask "NABS_MASTER_KEY (44 karakter base64)" "$(gen)")
    JWT_SECRET=$(ask "JWT_SECRET" "$(gentok)")
    SFTPGO_WEBHOOK_SECRET=$(ask "SFTPGO_WEBHOOK_SECRET" "$(gentok)")
    POSTGRES_PASSWORD=$(ask "PostgreSQL parolası" "$(gentok)")
    GF_PASS=$(gentok)
  fi

  # ---- 4) Secret backend ----
  echo "  Secret saklama: ${B}1)${N} .env dosyası (basit)   ${B}2)${N} Gömülü Vault (kalıcı, üretim)"
  SB=$(ask "Seçim" "1")
  [ "$SB" = "2" ] && USE_VAULT=1

  # ---- 5) TLS ----
  if [ "$DOMAIN" != "localhost" ]; then
    echo "  TLS: ${B}1)${N} Yok   ${B}2)${N} Otomatik HTTPS (Caddy/Let's Encrypt)   ${B}3)${N} Sonra GUI'den yükle"
    TLS=$(ask "Seçim" "2")
  else TLS="1"; fi

  # ---- 6) Observability ----
  yesno "Observability (Prometheus + Grafana) kurulsun mu?" "h" && OBS=1 || OBS=0

  # ---- 7) AI / Ollama ----
  OLLAMA_EP="http://host.docker.internal:11434/api/generate"
  if yesno "Yerel LLM (Ollama) için adres girmek ister misiniz? (Hayır → AI özellikleri pasif kalır)" "h"; then
    OLLAMA_EP=$(ask "Ollama generate URL" "$OLLAMA_EP")
  fi

  # ---- CORS ----
  if [ "$DOMAIN" = "localhost" ]; then CORS="http://localhost:5173"
  elif [ "$TLS" = "1" ]; then CORS="http://$DOMAIN"
  else CORS="https://$DOMAIN"; fi

  # ---- .env yaz ----
  say ".env yazılıyor"
  {
    echo "# NABS-GP — install.sh tarafından üretildi $(date -u +%FT%TZ)"
    echo "APP_ENV=production"
    echo "POSTGRES_USER=nabs_admin"
    echo "POSTGRES_PASSWORD=${POSTGRES_PASSWORD}"
    echo "POSTGRES_DB=nabs_governance"
    echo "DATABASE_URL=postgresql://nabs_admin:${POSTGRES_PASSWORD}@nabs-db:5432/nabs_governance"
    echo "REDIS_URL=redis://nabs-redis:6379/0"
    echo "JWT_EXPIRE_MINUTES=60"
    echo "CORS_ORIGINS=${CORS}"
    echo "NABS_GIT_REPO_PATH=/var/nabs/git_repo"
    echo "SFTPGO_UPLOAD_ROOT=/var/nabs/sftpgo_uploads"
    echo "SFTPGO_HTTPD__BINDINGS__0__PORT=8080"
    echo "OLLAMA_ENDPOINT=${OLLAMA_EP}"
    echo "OLLAMA_MODEL=llama3:8b-instruct"
    echo "OLLAMA_EMBED_ENDPOINT=${OLLAMA_EP%/generate}/embeddings"
    echo "OLLAMA_EMBED_MODEL=nomic-embed-text"
    echo "DATA_RETENTION_DAYS=365"
    echo "DB_BACKUP_RETENTION_DAYS=14"
    echo "GF_SECURITY_ADMIN_PASSWORD=${GF_PASS}"
    [ "$DOMAIN" != "localhost" ] && echo "NABS_DOMAIN=${DOMAIN}"
    if [ "$USE_VAULT" = "1" ]; then
      echo "# Bootstrap secret'ları Vault'ta (vault_init.sh yazar). Token aşağıya eklenecek."
      echo "VAULT_ADDR=http://nabs-vault:8200"
      echo "VAULT_KV_MOUNT=secret"
      echo "VAULT_SECRET_PATH=nabs-gp"
    else
      echo "NABS_MASTER_KEY=${NABS_MASTER_KEY}"
      echo "JWT_SECRET=${JWT_SECRET}"
      echo "SFTPGO_WEBHOOK_SECRET=${SFTPGO_WEBHOOK_SECRET}"
    fi
  } > .env
  chmod 600 .env
  ok ".env oluşturuldu (0600)"

  # compose overlay'leri
  [ "${TLS:-1}" = "2" ] && COMPOSE_FILES+=(-f docker-compose.tls.yml)
  [ "${OBS:-0}" = "1" ]  && COMPOSE_FILES+=(-f docker-compose.observability.yml)
  [ "$USE_VAULT" = "1" ] && COMPOSE_FILES+=(-f docker-compose.vault.yml)
  # seçim özetini sonrası için sakla
  export NABS_MASTER_KEY JWT_SECRET SFTPGO_WEBHOOK_SECRET
else
  # mevcut .env; vault kullanılıyor mu tahmin et
  grep -q '^VAULT_ADDR=' .env && { USE_VAULT=1; COMPOSE_FILES+=(-f docker-compose.vault.yml); }
  grep -q '^NABS_DOMAIN=' .env && [ -f docker-compose.tls.yml ] && \
    yesno "TLS (Caddy) overlay'i kullanılsın mı?" "e" && COMPOSE_FILES+=(-f docker-compose.tls.yml)
fi

# ---- 8) Vault ilk kurulum ----
if [ "$USE_VAULT" = "1" ]; then
  echo; say "Gömülü Vault başlatılıyor"
  $DC "${COMPOSE_FILES[@]}" up -d nabs-vault
  sleep 3
  say "Vault init + unseal + secret yazma (scripts/vault_init.sh)"
  ./scripts/vault_init.sh
  APP_TOKEN=$(grep -m1 'App Token' vault-init.secret 2>/dev/null | awk '{print $NF}' || true)
  if [ -n "${APP_TOKEN:-}" ]; then
    grep -q '^VAULT_TOKEN=' .env && sed -i.bak "s|^VAULT_TOKEN=.*|VAULT_TOKEN=${APP_TOKEN}|" .env \
      || echo "VAULT_TOKEN=${APP_TOKEN}" >> .env
    rm -f .env.bak
    ok "VAULT_TOKEN .env'e yazıldı"
  else
    warn "App token otomatik alınamadı. vault-init.secret'tan VAULT_TOKEN'ı .env'e elle ekleyin."
  fi
fi

# ---- 9) Stack'i başlat ----
echo; say "Stack derleniyor ve başlatılıyor (birkaç dakika sürebilir)"
$DC "${COMPOSE_FILES[@]}" up -d --build

# ---- 10) API sağlık bekle ----
say "API sağlığı bekleniyor"
for i in $(seq 1 30); do
  if curl -fs http://localhost:8000/health >/dev/null 2>&1; then ok "API hazır"; break; fi
  sleep 2
  [ "$i" = "30" ] && warn "API 60 sn içinde yanıt vermedi; 'docker compose logs nabs-core-api' ile bakın."
done

# ---- 11) Admin oluştur ----
echo; say "İlk admin kullanıcısı"
ADMIN_USER=$(ask "Admin kullanıcı adı" "admin")
ADMIN_PASS=$(ask_secret "Admin parolası (boş → otomatik üret)")
if [ -z "$ADMIN_PASS" ]; then ADMIN_PASS=$(gentok); GENERATED_PASS=1; else GENERATED_PASS=0; fi
if $DC "${COMPOSE_FILES[@]}" exec -T nabs-core-api python -m app.cli create-admin "$ADMIN_USER" "$ADMIN_PASS" >/dev/null 2>&1; then
  ok "Admin '$ADMIN_USER' oluşturuldu"
else
  warn "Admin oluşturulamadı (belki zaten var). Elle: $DC exec nabs-core-api python -m app.cli create-admin <kullanıcı> <parola>"
fi

# ---- 12) Özet ----
URL="http://localhost:5173"
[ "${TLS:-1}" = "2" ] && URL="https://${DOMAIN}"
echo
echo "${G}${B}  Kurulum tamamlandı.${N}"
echo "  ${B}GUI:${N}   $URL"
echo "  ${B}API:${N}   http://localhost:8000/api/docs"
[ "${OBS:-0}" = "1" ] && echo "  ${B}Grafana:${N} http://localhost:3000  (admin / .env GF_SECURITY_ADMIN_PASSWORD)"
echo "  ${B}Admin:${N} $ADMIN_USER"
[ "${GENERATED_PASS:-0}" = "1" ] && echo "  ${B}Admin parolası:${N} ${Y}$ADMIN_PASS${N}  ${D}(kaydedin!)${N}"
if [ "$USE_VAULT" = "1" ]; then
  echo "  ${Y}Vault:${N} unseal anahtarı + token → ${B}vault-init.secret${N} (GÜVENLE SAKLAYIN, sunucudan taşıyın)."
  echo "         Her restart'ta: ${B}./scripts/vault_unseal.sh${N}"
fi
echo "  ${D}Detaylı işletim: docs/PRODUCTION_INSTALL.md${N}"
echo
