#!/usr/bin/env bash
# ============================================================================
# IEEE OUI veritabanını indirir → deploy/oui/oui.csv
#
#   ./scripts/fetch_oui.sh
#
# Bu dosya olmadan uç cihazların üreticisi 'unknown' görünür (gömülü tablo
# yalnızca ~50 ağ üreticisi içerir; IEEE kaydında 50 binden fazla tahsis var).
#
# İnternet erişimi olmayan kurulumlarda: dosyayı başka bir makinede indirip
# deploy/oui/oui.csv olarak kopyalayın. IEEE oui.csv, IEEE oui.txt ve
# nmap/wireshark biçimlerinin üçü de okunabiliyor.
# ============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

DEST_DIR="deploy/oui"
DEST="$DEST_DIR/oui.csv"
mkdir -p "$DEST_DIR"

SOURCES=(
  "https://standards-oui.ieee.org/oui/oui.csv"
  "https://standards-oui.ieee.org/oui/oui.txt"
)

for url in "${SOURCES[@]}"; do
  echo "==> deneniyor: $url"
  if curl -fsSL --max-time 120 -o "$DEST.tmp" "$url" && [ "$(wc -c < "$DEST.tmp")" -gt 100000 ]; then
    mv "$DEST.tmp" "$DEST"
    lines=$(grep -c . "$DEST" 2>/dev/null || echo "?")
    echo "    ✓ indirildi: $DEST ($lines satır)"
    echo
    echo "Etkinleştirmek için servisleri yeniden başlatın:"
    echo "    docker compose -f docker-compose.yml -f docker-compose.prod.yml restart nabs-core-api celery-worker-high celery-beat"
    exit 0
  fi
  rm -f "$DEST.tmp"
  echo "    başarısız"
done

echo
echo "HATA: OUI veritabanı indirilemedi (internet erişimi yok olabilir)." >&2
echo "Çözüm: dosyayı erişimi olan bir makinede indirip buraya kopyalayın:" >&2
echo "    $PWD/$DEST" >&2
echo "Kaynak: https://standards-oui.ieee.org/oui/oui.csv" >&2
exit 1
