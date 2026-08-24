#!/usr/bin/env bash
# ============================================================================
# NABS-GP — cihaz SSH teşhis aracı
#
#   ./scripts/diag_device_ssh.sh <cihaz-ip> [vendor] [kullanıcı]
#   ör:  ./scripts/diag_device_ssh.sh 10.10.0.21 huawei_vrp admin
#
# Yedeği ALAN konteynerin (celery-worker-high) içinden çalışır; yani ağ yolu,
# ssh sürümü ve legacy algoritma ayarı gerçekte kullanılanla birebir aynıdır.
# Cihaza yalnızca okuma amaçlı bağlanır, hiçbir komut yazmaz.
# ============================================================================
set -uo pipefail

HOST="${1:-}"
VENDOR="${2:-}"
USER_NAME="${3:-admin}"
CONTAINER="${NABS_CONTAINER:-celery-worker-high}"
SSH_CFG="/srv/nabs/ssh_config"

[ -z "$HOST" ] && { echo "Kullanım: $0 <cihaz-ip> [vendor] [kullanıcı]"; exit 1; }

if [ -t 1 ]; then B=$(printf '\033[1m'); G=$(printf '\033[32m'); Y=$(printf '\033[33m')
  R=$(printf '\033[31m'); C=$(printf '\033[36m'); N=$(printf '\033[0m')
else B=""; G=""; Y=""; R=""; C=""; N=""; fi
say(){ echo; echo "${C}==>${N} ${B}$*${N}"; }
ok(){ echo "  ${G}✓${N} $*"; }
bad(){ echo "  ${R}✗${N} $*"; }
warn(){ echo "  ${Y}!${N} $*"; }

dex(){ docker exec -i "$CONTAINER" "$@"; }

say "0) Konteyner erişilebilir mi"
if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
  bad "'$CONTAINER' konteyneri yok. Çalışanlar:"; docker ps --format '    {{.Names}}'; exit 1
fi
ok "$CONTAINER bulundu"

say "1) Legacy SSH yapılandırması imajda var mı"
if dex test -f "$SSH_CFG"; then
  ok "$SSH_CFG mevcut"
else
  bad "$SSH_CFG YOK — eski Huawei/Fortinet cihazları modern algoritmalarla"
  bad "reddedilir ('no matching key exchange method found')."
  warn "Çözüm: imajı yeniden derleyin →  docker compose build --no-cache && docker compose up -d"
  echo
fi

say "2) Cihaz TCP/22'de açık mı"
if dex timeout 8 bash -c "cat < /dev/null > /dev/tcp/$HOST/22" 2>/dev/null; then
  ok "$HOST:22 erişilebilir"
else
  bad "$HOST:22'ye TCP bağlantısı kurulamadı (yönlendirme / ACL / firewall?)"
  warn "Sonraki adımlar anlamsız olabilir."
fi

say "3) Cihazın önerdiği algoritmalar"
dex timeout 15 ssh -vv -o BatchMode=yes -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
  "nonexistent@$HOST" exit 2>&1 |
  grep -iE "peer server KEXINIT|kex_exchange|no matching|Their offer|remote software version" |
  sed 's/^/    /' | head -12

say "4) NABS ssh_config OLMADAN (modern varsayılanlar)"
OUT_NOCFG=$(dex timeout 20 ssh -o BatchMode=yes -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
  "$USER_NAME@$HOST" exit 2>&1)
echo "$OUT_NOCFG" | sed 's/^/    /' | head -6

say "5) NABS ssh_config İLE (üretimde kullanılan yol)"
if dex test -f "$SSH_CFG"; then
  OUT_CFG=$(dex timeout 20 ssh -F "$SSH_CFG" -o BatchMode=yes -o ConnectTimeout=10 \
    "$USER_NAME@$HOST" exit 2>&1)
  echo "$OUT_CFG" | sed 's/^/    /' | head -6
  if echo "$OUT_NOCFG" | grep -qi "no matching" && ! echo "$OUT_CFG" | grep -qi "no matching"; then
    ok "Legacy algoritma ayarı sorunu çözüyor — kripto uyuşmazlığı kalmadı."
  fi
  if echo "$OUT_CFG" | grep -qiE "Permission denied|password"; then
    ok "Kripto el sıkışması BAŞARILI (yalnız parola sorulmuş). Sorun kimlik bilgisinde."
  fi
  if echo "$OUT_CFG" | grep -qi "no matching"; then
    bad "Legacy ayara rağmen algoritma uyuşmazlığı sürüyor."
    warn "Cihazın önerdiklerini (3. adım) ssh_config'e ekleyin: backend/deploy/ssh_config"
  fi
else
  warn "ssh_config olmadığı için bu adım atlandı."
fi

if [ -n "$VENDOR" ]; then
  say "6) Gerçek yedekleme kod yolu ($VENDOR)"
  warn "Parola istenecek; ekrana yazılmaz ve hiçbir yere kaydedilmez."
  read -rs -p "    $USER_NAME parolası: " DEV_PASS; echo
  DEV_PASS="$DEV_PASS" docker exec -i -e DEV_PASS \
    -e DIAG_HOST="$HOST" -e DIAG_USER="$USER_NAME" -e DIAG_VENDOR="$VENDOR" \
    "$CONTAINER" python - <<'PY'
import os, logging, sys
logging.basicConfig(level=logging.INFO, format="    %(levelname)s %(name)s: %(message)s")
from app.workers.tasks import _fetch_config_over_ssh, _scrapli_ssh_kwargs
print("    kullanilan ssh kwargs:", _scrapli_ssh_kwargs())
try:
    out = _fetch_config_over_ssh(os.environ["DIAG_HOST"], os.environ["DIAG_USER"],
                                 os.environ["DEV_PASS"], None, os.environ["DIAG_VENDOR"])
    print(f"    BASARILI — {len(out)} karakter config alindi. Ilk satirlar:")
    for line in out.splitlines()[:5]:
        print("      " + line)
except Exception as exc:
    print(f"    HATA: {type(exc).__name__}: {exc}")
    sys.exit(1)
PY
fi

say "Özet"
echo "  · 1. adım ✗ ise  → imajı yeniden derleyin (ssh_config imajda yok)."
echo "  · 2. adım ✗ ise  → ağ/ACL sorunu; kodla ilgisi yok."
echo "  · 4 ✗ / 5 ✓ ise  → legacy kripto sorunuydu, ayar çalışıyor."
echo "  · 5. adım 'Permission denied' → kripto tamam, kimlik bilgisi yanlış."
echo "  · 5 de ✗ ise     → 3. adımdaki algoritmaları backend/deploy/ssh_config'e ekleyin."
echo
