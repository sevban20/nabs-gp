#!/usr/bin/env bash
# ============================================================================
# NABS-GP — stack teşhisi (502 / servis ayağa kalkmıyor durumları için)
#
#   ./scripts/diag_stack.sh
#
# Sadece okur; hiçbir şeyi değiştirmez. Çıktıyı olduğu gibi paylaşabilirsiniz —
# parola/secret değerleri basılmaz, yalnızca "tanımlı/tanımsız" bilgisi verilir.
# ============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

if [ -t 1 ]; then B=$(printf '\033[1m'); G=$(printf '\033[32m'); Y=$(printf '\033[33m')
  R=$(printf '\033[31m'); C=$(printf '\033[36m'); D=$(printf '\033[2m'); N=$(printf '\033[0m')
else B=""; G=""; Y=""; R=""; C=""; D=""; N=""; fi
say(){ echo; echo "${C}==>${N} ${B}$*${N}"; }
ok(){ echo "  ${G}✓${N} $*"; }
bad(){ echo "  ${R}✗${N} $*"; }
warn(){ echo "  ${Y}!${N} $*"; }

ALL="nabs-postgres nabs-redis nabs-api celery-worker-high celery-beat nabs-dashboard sftpgo-gateway nabs-vault nabs-caddy"

say "1) Konteyner durumları"
printf "    %-22s %-12s %-12s %s\n" "AD" "DURUM" "SAĞLIK" "YENİDEN BAŞLATMA"
for c in $ALL; do
  if ! docker inspect "$c" >/dev/null 2>&1; then
    printf "    %-22s %s\n" "$c" "${D}yok${N}"; continue
  fi
  st=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null)
  he=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}-{{end}}' "$c" 2>/dev/null)
  rc=$(docker inspect -f '{{.RestartCount}}' "$c" 2>/dev/null)
  col=""; [ "$st" != "running" ] && col="$R"; [ "$he" = "unhealthy" ] && col="$R"
  printf "    %-22s ${col}%-12s %-12s${N} %s\n" "$c" "$st" "$he" "$rc"
done

say "2) Caddy arkadaki servislere ulaşabiliyor mu (502'nin kaynağı)"
if docker inspect nabs-caddy >/dev/null 2>&1; then
  for target in "nabs-dashboard:80" "nabs-core-api:8000/health"; do
    if docker exec nabs-caddy wget -q -T 5 -O /dev/null "http://$target" 2>/dev/null; then
      ok "caddy → $target ulaşılabilir"
    else
      bad "caddy → $target ULAŞILAMIYOR  ← 502'nin sebebi bu"
    fi
  done
else
  warn "nabs-caddy yok (TLS overlay'i kullanılmıyor olabilir)"
fi

say "3) API kendi içinden sağlıklı mı"
if docker inspect nabs-api >/dev/null 2>&1; then
  out=$(docker exec nabs-api python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=5).read().decode())" 2>&1)
  case "$out" in
    *'"status":"ok"'*) ok "/health → $out" ;;
    *) bad "/health yanıt vermedi:"; echo "$out" | sed 's/^/      /' | head -5 ;;
  esac
else
  bad "nabs-api konteyneri yok"
fi

say "4) API logu (son 25 satır)"
docker logs --tail 25 nabs-api 2>&1 | sed 's/^/    /' || echo "    (log yok)"

say "5) Dashboard (nginx) logu (son 10 satır)"
docker logs --tail 10 nabs-dashboard 2>&1 | sed 's/^/    /' || echo "    (log yok)"

say "6) Caddy logu (son 20 satır) — sertifika/ACME hataları burada görünür"
docker logs --tail 20 nabs-caddy 2>&1 | sed 's/^/    /' || echo "    (log yok)"

say "7) Redis kimlik doğrulaması"
if docker inspect nabs-redis >/dev/null 2>&1; then
  if docker exec nabs-redis sh -c 'redis-cli -a "$REDIS_PASSWORD" ping 2>/dev/null' | grep -q PONG; then
    ok "redis parolayla yanıt veriyor"
  elif docker exec nabs-redis redis-cli ping 2>/dev/null | grep -q PONG; then
    warn "redis PAROLASIZ yanıt veriyor (prod overlay etkin değil)"
  else
    bad "redis yanıt vermiyor"
  fi
fi

say "8) Veritabanı kimlik doğrulaması"
if docker inspect nabs-postgres >/dev/null 2>&1; then
  PGU=$(grep -m1 '^POSTGRES_USER=' .env 2>/dev/null | cut -d= -f2-)
  PGP=$(grep -m1 '^POSTGRES_PASSWORD=' .env 2>/dev/null | cut -d= -f2-)
  PGD=$(grep -m1 '^POSTGRES_DB=' .env 2>/dev/null | cut -d= -f2-)
  # DATABASE_URL içindeki parola POSTGRES_PASSWORD ile aynı olmalı
  DBU_PASS=$(grep -m1 '^DATABASE_URL=' .env 2>/dev/null | sed -n 's|^DATABASE_URL=.*://[^:]*:\([^@]*\)@.*|\1|p')
  dupes=$(grep -c '^POSTGRES_PASSWORD=' .env 2>/dev/null || echo 0)
  [ "$dupes" -gt 1 ] && bad ".env içinde POSTGRES_PASSWORD $dupes kez tanımlı — sonuncusu geçerli olur, karışıklık kaynağı."
  if [ -n "$DBU_PASS" ] && [ "$DBU_PASS" != "$PGP" ]; then
    bad "DATABASE_URL içindeki parola POSTGRES_PASSWORD ile AYNI DEĞİL — API bağlanamaz."
  else
    ok "DATABASE_URL ve POSTGRES_PASSWORD tutarlı"
  fi
  if docker exec -e PGPASSWORD="$PGP" nabs-postgres        psql -h 127.0.0.1 -U "$PGU" -d "$PGD" -c 'select 1' >/dev/null 2>&1; then
    ok "veritabanı .env parolasıyla bağlantıyı kabul ediyor"
  else
    bad "veritabanı .env parolasını REDDEDİYOR (volume eski kurulumdan kalmış olabilir)"
    warn "Düzeltme (veriler korunur):"
    echo "    docker exec nabs-postgres psql -U $PGU -d $PGD \\"
    echo "      -c \"ALTER USER \\\"$PGU\\\" WITH PASSWORD '<POSTGRES_PASSWORD>';\""
    echo "    docker restart nabs-api celery-worker-high celery-beat"
  fi
fi

say "9) Vault durumu"
if docker inspect nabs-vault >/dev/null 2>&1; then
  vs=$(docker exec -e VAULT_ADDR=http://127.0.0.1:8200 nabs-vault vault status 2>&1); rc=$?
  case $rc in
    0) ok "unsealed" ;;
    2) bad "SEALED — API secret'ları okuyamaz ve fail-closed açılmaz. Çözüm: ./scripts/vault_unseal.sh" ;;
    *) bad "erişilemiyor (rc=$rc)" ;;
  esac
  echo "$vs" | grep -iE "^(Initialized|Sealed|Storage Type|Version)" | sed 's/^/      /'
fi

say "10) .env anahtarları (değerler gösterilmez)"
for k in APP_ENV DATABASE_URL REDIS_URL REDIS_PASSWORD CORS_ORIGINS NABS_DOMAIN \
         VAULT_ADDR VAULT_TOKEN NABS_MASTER_KEY JWT_SECRET; do
  if grep -q "^$k=" .env 2>/dev/null; then
    v=$(grep -m1 "^$k=" .env | cut -d= -f2-)
    case "$k" in
      CORS_ORIGINS|NABS_DOMAIN|APP_ENV|VAULT_ADDR) printf "    %-20s = %s\n" "$k" "$v" ;;
      REDIS_URL) printf "    %-20s = %s\n" "$k" "$(echo "$v" | sed 's|://[^@]*@|://***@|')" ;;
      *) printf "    %-20s = %s\n" "$k" "${G}tanımlı${N}" ;;
    esac
  else
    printf "    %-20s = %s\n" "$k" "${D}yok${N}"
  fi
done

say "11) Kullanılan compose dosyaları"
ls -1 docker-compose*.yml | sed 's/^/    /'
warn "Stack'i başlatırken hangi -f dosyalarını verdiğinizi de paylaşın."

say "Özet ipuçları"
echo "  · 2. adımda 'nabs-core-api:8000' ulaşılamıyorsa → API ayakta değil, 4. adımdaki loga bakın."
echo "  · 2. adımda 'nabs-dashboard:80' ulaşılamıyorsa → frontend konteyneri çökmüş."
echo "  · 9. adımda SEALED ise → API fail-closed açılmaz; unseal edin."
echo "  · 6. adımda ACME/sertifika hatası varsa → iç alan adı (.local) için Caddyfile'da"
echo "    'tls internal' satırını açın; Let's Encrypt iç alan adına sertifika veremez."
echo
