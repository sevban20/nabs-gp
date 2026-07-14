# NABS-GP — Network Asset, Backup & Security Governance Platform

Teknik Şartname v1.1'in **tüm fazları (Faz 1-5) ve tüm bölümleri (1-15)** kapsayan uygulaması. FastAPI + Celery/Redis + PostgreSQL + Git tabanlı ağ cihazı konfigürasyon yedekleme, güvenlik denetimi ve yönetişim sistemi.

## Admin Ayarlar paneli
Operasyonel ayarlar (bildirim webhook'ları, veri saklama süresi, login rate-limit, drift önem derecesi, Ollama adresi/modeli, LDAP) **Sistem → Ayarlar** sekmesinden (admin) yönetilir; DB'de tutulur ve canlı etki eder (restart gerekmez). Çözümleme önceliği: DB override → ortam değişkeni → varsayılan. Secret'lı alanlar (Slack/Teams webhook) maskeli gösterilir. **Bootstrap secret'ları (NABS_MASTER_KEY, JWT_SECRET, DB parolası) güvenlik gereği burada YÖNETİLMEZ** — onlar env ya da Vault'ta kalır (tavuk-yumurta: DB'deki her şeyi bunlar şifreler).

## Kullanıcı yönetimi & sistem doğrulama (admin)
**Yönetim** sekmesinde kullanıcı yönetimi: oluştur, rol ata (viewer/operator/approver/admin), aktif/pasifleştir, parola sıfırla, sil. Kilitlenmeyi önleyen korumalar: son aktif admin düşürülemez/pasifleştirilemez/silinemez; admin kendini pasifleştiremez/silemez.

**Ayarlar → Sistem Durumu & Testler** (admin): (1) **Secret kaynağı** — Vault aktif/erişilebilir mi, bootstrap secret'ları hangi kaynaktan (vault/env) çözülüyor; (2) **Web sunucu TLS sertifikası** — GUI erişiminde kullanılan sertifikayı yükle/güncelle: PEM cert + private key GUI'den yüklenir, backend doğrular (anahtar-sertifika eşleşmesi, süre) ve reverse-proxy'nin okuduğu paylaşımlı volume'a yazar (key 0600 izinle; asla geri döndürülmez). Caddy dosya değişince otomatik yeniler — kullanmak için `docker-compose.tls.yml` + `deploy/Caddyfile.uploaded`; (3) **TLS durum kontrolü** — platform (ya da verilen host) sertifikasını canlı okur: konu, veren, bitiş, kalan gün, yaklaşan-bitiş uyarısı, self-signed tespiti; (4) **LDAP testi** — yapılandırmayı test eder (bind ya da sunucu erişim kontrolü). Böylece prod öncesi tüm bu işlemler GUI'den doğrulanabilir.

## Üretim / deploy notları
- **Secret'lar (env veya Vault):** Test için `.env` yeterli. Üretim için Vault: `.env`'de `VAULT_ADDR` + `VAULT_TOKEN` (ya da AppRole) tanımlanınca `NABS_MASTER_KEY`, `JWT_SECRET`, `SFTPGO_WEBHOOK_SECRET` Vault KV v2'den okunur (yoksa env'e düşer; Vault tanımlı ama erişilemezse fail-closed hata verir, yanlış anahtarla açılmaz).
- **CORS:** `.env`'de `CORS_ORIGINS`'i dashboard'un gerçek origin'ine ayarlayın (TLS arkasında `https://...`).
- **TLS:** `docker-compose.tls.yml` (Caddy, otomatik HTTPS). `NABS_DOMAIN=nabs.sirket.local docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d`. İç ağ için Caddyfile'da `tls internal` satırını açın.
- **Non-root:** API/worker konteynerleri `appuser` (uid 10001) ile çalışır.
- **Kalan üretim maddeleri:** Alembic'e geçiş (şu an hafif migrator), 5.000 düğüm yük testi (`loadtest/locustfile.py`), OWASP pentest, retention pencerelerinin hukuk onayı — spec Bölüm 15 açık maddeleri.

### Hızlı kurulum — sihirbaz (önerilen)
Arşivi açın ve çalıştırın:
```bash
./install.sh
```
Sihirbaz gerekli soruları sorar (alan adı, secret'lar, Vault/TLS/observability, Ollama, admin), `.env`'i üretir, stack'i kurar, admin'i oluşturur ve sağlık kontrolü yapar. Enter ile varsayılanlar kabul edilir. Detaylı işletim: `docs/PRODUCTION_INSTALL.md`.

### Manuel kurulum
```bash
cp .env.example .env
python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"   # NABS_MASTER_KEY
# .env: NABS_MASTER_KEY, JWT_SECRET, POSTGRES_PASSWORD, SFTPGO_WEBHOOK_SECRET doldurun
docker compose up -d --build
docker exec -it nabs-api python -m app.cli create-admin admin 'GüçlüParola1!'
```

## Faz kapsamı

| Faz / Bölüm | Gereksinim | Uygulama |
|---|---|---|
| **Faz 1** | DB şeması, AES-256 kasa, FastAPI, JWT, Celery/Redis, Scrapli, maskeleme, Git, SFTPGo webhook | `db/init.sql`, `app/core/`, `app/services/`, `app/workers/`, `endpoints/webhooks.py` |
| **Faz 2** | SNMP/ping keşfi, OS tanıma, diff motoru, React dashboard, RBAC, immutable audit | `services/discovery.py`, `endpoints/discovery.py`, `core/audit.py`, `frontend/`, rol kontrolleri |
| **Faz 3** | YAML politika motoru, CVE/CPE eşleme, risk skorlama, PDF raporlama | `services/policy_engine.py` + `policies/`, `services/cve_sync.py`, `services/risk_engine.py`, `services/reporting.py` |
| **Faz 4** | LLM çelişki analizi, pgvector RAG, Chat-with-Network, remediation üretimi + onay makinesi, değişiklik özetleme | `ai/analyzer.py`, `ai/rag.py`, `endpoints/ai.py`, `endpoints/remediations.py` |
| **Faz 5** | Slack/Teams/Syslog alarmları, LDAP SSO + MFA, dağıtık worker, yük testi | `services/notifications.py`, `core/ldap_auth.py`, TOTP MFA (`endpoints/auth.py`), Celery kuyrukları, `loadtest/locustfile.py` |
| **Faz 6** (ek) | GUI'ye tam API entegrasyonu: varlık ekleme/silme, kimlik kasası yönetimi, kullanıcı+MFA, bulgu susturma, AI düzeltme üretimi, manuel düzeltme talebi, yedek geçmişi, AI diff özeti, benchmark indeksleme; rol-duyarlı arayüz | `frontend/src/components/` (AssetForm, Admin), genişletilmiş `api.js` |
| **Bölüm 11** | Prometheus/Grafana, JSON structured logging + request-ID | `core/observability.py`, `docker-compose.observability.yml`, `observability/prometheus.yml` |
| **Bölüm 12** | Git mirror, DB yedekleme, veri saklama (retention) | `mirror_git_repository` görevi, `scripts/backup_db.sh`, `purge_expired_records` görevi (`DATA_RETENTION_DAYS`) |

### Kod dışı kalan maddeler (doğası gereği)
GPU host tedariki ve Ollama model kurulumu (altyapı işlemi — kod hazır, `OLLAMA_*` env), SAML SSO/WebAuthn (kurumsal IdP entegrasyonu; LDAP+TOTP temeli mevcut), OWASP penetrasyon testi ve KVKK/GDPR hukuki onayı (insan süreci), cihaza yazma (write-back) bileşeni (Spec Bölüm 15'te bilinçli olarak kapsam dışı — İlke 13.5: onaysız hiçbir komut cihaza gidemez).

## Güvenlik tasarım kararları (Spec Bölüm 13)
Fail-closed: master key/JWT secret yoksa üretimde açılış reddedilir. Webhook HMAC'i ham gövde üzerinde doğrulanır, path-traversal engellenir. Maskeleme motoru çok-vendor'dur ve her kuralın unit testi vardır (spec taslağındaki regex `$` içermediğinden gerçek type-5 hash'leri kaçırıyordu — düzeltildi). Remediation onayında dört-göz ilkesi: onaylayan ≠ talep eden; CRITICAL/HIGH bulgular STAGED atlanamaz. Audit izi append-only'dir.

## Kurulum

### Docker ile (önerilen)
```bash
cp .env.example .env    # değerleri doldurun
# NABS_MASTER_KEY üretimi:
# python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
docker compose up -d --build
# Observability katmanı (opsiyonel):
docker compose -f docker-compose.yml -f docker-compose.observability.yml up -d
docker exec -it nabs-api python -m app.cli create-admin admin 'GüçlüParola1!'
```
**Dashboard (GUI): http://localhost:5173** — API: http://localhost:8000/docs — Prometheus: :9090 — Grafana: :3000

NMS-tarzı arayüz (sol menü + Genel Bakış paneli): **Genel Bakış** (KPI kartları, cihaz up/down ve risk donut'ları, 24s yedekleme, en riskli cihazlar, son bulgular akışı, vendor dağılımı — 30 sn'de bir otomatik yenilenir), **Cihazlar** (arama + up/down/riskli filtreleri, ekleme/silme, yedekleme, yedek geçmişi, config diff + AI özet), **Güvenlik Bulguları** (çözme/susturma, AI düzeltme üretimi), **Ağ Keşfi** (CIDR tarama), **Onay Akışı** (state machine + manuel talep), **AI Asistan** (Chat + PDF rapor), **Yönetim** (kimlik kasası, kullanıcı, MFA, benchmark indeksleme), **Entegrasyonlar & API** (API anahtarı üret/iptal, hızlı başlangıç, OpenAPI linkleri). Arayüz rol-duyarlıdır; asıl yetki kontrolü API tarafındadır. Giriş: `create-admin` ile oluşturduğunuz kullanıcı.

### Config drift & zamanlanmış uyumluluk
Her cihaza bir **golden (referans) config** işaretlenebilir: Cihazlar listesinde "Baz Al" veya `POST /api/v1/assets/{id}/baseline` mevcut (en son yedeklenmiş) config'i referans olarak sabitler. Sistem sapmayı iki noktada tespit eder: (1) her yeni yedekte otomatik, (2) saatte bir çalışan zamanlanmış uyumluluk taraması (`run_compliance_sweep`, yeni yedek beklemeden). Sapma bulununca `CONFIG-DRIFT` advisory'si açılır ve cihaz `has_drift` işaretlenir; config referansa dönünce advisory otomatik kapanır. "Baz Al" ile mevcut sapma onaylanmış kabul edilip yeni golden olur.

GUI: Cihazlar tablosunda drift/senkron rozeti, satırda "Drift" (golden'a göre diff'i renkli gösterir) ve "Baz Al" butonları; Genel Bakış'ta "Config Drift" KPI'ı. Uçlar: `GET /assets/{id}/drift` (anlık durum + diff), `GET /compliance/drift` (filo geneli), `POST /compliance/sweep` (manuel tarama).

### Yerel LLM (Ollama) — harici, opsiyonel
AI özellikleri (Chat-with-Network, düzeltme üretimi, değişiklik özeti, RAG) yerel bir Ollama sunucusu gerektirir. Ollama **stack'e gömülü değildir**; ayrı çalıştırılır ki her ortamda (GPU'lu sunucu ya da CPU'lu makine) esnek olsun. LLM erişilemezse uygulama çökmez, ilgili uçlar 503 + açıklayıcı mesaj döner ve Chat sekmesinde bir durum rozeti (bağlı / model yüklü değil / erişilemez) gösterilir.

Mac (native, GPU hızlandırmalı — M2'de önerilen):
```bash
brew install ollama && ollama serve
ollama pull llama3:8b-instruct && ollama pull nomic-embed-text
```
Ayrı bir sunucuda konteynerle (CPU varsayılan, GPU notu dosyada):
```bash
docker compose -f docker-compose.ollama.yml up -d
docker exec nabs-ollama ollama pull llama3:8b-instruct
docker exec nabs-ollama ollama pull nomic-embed-text
```
Docker içindeki API host'taki Ollama'ya `host.docker.internal:11434` üzerinden ulaşır (`.env`'de ayarlı; Linux için compose'da `extra_hosts` var). Farklı bir sunucudaki Ollama için `.env`'de `OLLAMA_ENDPOINT`/`OLLAMA_EMBED_ENDPOINT`'i o adrese çevirin. Bağlantıyı `GET /api/v1/ai/status` ile kontrol edebilirsiniz.

### Desteklenen cihaz tipleri
Ağ-vendor CLI cihazları: Cisco IOS/IOS-XE, Palo Alto PAN-OS, Juniper Junos, Huawei VRP, Aruba OS-CX, Aruba/HP ProCurve, MikroTik RouterOS (Scrapli network sürücüsü, scrapli-community gerektirir). **Fortinet ailesi (FortiGate/FortiSwitch)** scrapli-community'de ağ platformu olmadığından Scrapli GenericDriver ile ham komut çalıştırılarak yedeklenir (sayfalama otomatik kapatılır).

SSH bağlantısı için worker imajında `openssh-client` kuruludur (Scrapli 'system' transport). Eski cihazlar (Huawei/Fortinet vb.) modern OpenSSH'in kapattığı legacy KEX/cipher algoritmalarını isteyebilir; bunlar için uyumluluk odaklı `backend/deploy/ssh_config` imaja gömülür ve tüm SSH çağrılarında kullanılır (`NABS_SSH_CONFIG` ile özelleştirilebilir). Tanıma SNMP sysDescr + SSH banner imzalarıyla otomatik yapılır; her cihazın kendi read-only yedekleme komutu vardır (`display current-configuration`, `show running-config`, `/export` vb.).

**OpenWrt / Linux** ayrı bir yoldan desteklenir: ağ-vendor CLI değil, bir Linux kutusu olduğu için Scrapli yerine paramiko ile `uci export` çalıştırılır (tüm yapılandırmayı düz metin verir; diff ve sanitizasyona ideal, uci yoksa `/etc/config/*`'a düşer). Yani lokal ağındaki bir OpenWrt router'ını envantere `openwrt` vendor'ıyla ekleyip ACTIVE_SSH ile yedekleyebilirsin. Maskeleme motoru UCI (`option key/password/psk`), Huawei cipher parolaları ve MikroTik PSK'lerini de kapsar.

### Katmanlı ağ keşfi ve ağ haritası
Keşif artık tek sinyal (SNMP) yerine katmanlı çalışır: TCP probe ile canlılık, sonra sırayla SNMP sysDescr → SSH banner fingerprint ile vendor/OS tanıma. Her sonuç hangi sinyalle tanındığını `discovery_source` (SNMP / SSH_BANNER / TCP_PROBE) ile bildirir; SNMP'si kapalı cihazlar da yakalanır.

Komşuluk keşfi (LLDP/CDP) topoloji üretir: bir cihaza SSH ile bağlanıp komşu tablosu okunur (`POST /api/v1/topology/collect/{asset_id}`, GUI'de Cihazlar → "Komşuları Tara"). Bu, taramayla asla görülemeyecek cihazları (SNMP kapalı, ping'e cevapsız) ortaya çıkarır. **Ağ Haritası** sekmesi (`GET /api/v1/topology/graph`) bu link'lerden bağımlılıksız SVG force-directed bir harita çizer: düğüm rengi = risk, kesikli halka = down, gri düğüm = yönetilmeyen (yalnızca komşuluktan bilinen, envantere eklenmeye aday) cihaz.

**L2 uç cihaz keşfi (ARP + MAC tablosu + OUI):** Cihazlar → "L2 Topla" bir switch/router'dan `show ip arp` + `show mac address-table` çeker; ARP (ip↔mac) ve MAC tablosunu (mac↔port) birleştirip uç cihazları çıkarır, MAC'in ilk 3 oktetinden (OUI) üreticiyi tahmin eder. Sonuçlar Keşif → **Keşfedilen Cihazlar** panelinde listelenir: MAC, üretici (Cisco/Aruba/VMware/Raspberry Pi…), IP, görüldüğü switch + port + VLAN, kaynak. Multi-site kurulumlarda her yönetilen cihaz kendi segmentindeki uç cihazları raporlar, böylece dağınık lokasyonların envanteri tek yerde toplanır. Network admin buradan bir host'u **Onboard** edip (envantere ekler) ya da seçili bir kimlik bilgisiyle **SSH Dene** ile tek seferlik bağlantı doğrulaması yapabilir (toplu "credential spray" yapılmaz — hesap kilitlenme riski).

### Harici entegrasyon (API anahtarı)
Yönetim yetkisiyle **Entegrasyonlar & API** sekmesinden anahtar üretilir (ham anahtar yalnızca bir kez gösterilir, DB'de SHA-256 özeti saklanır). İstemciler `X-API-Key` başlığıyla kimliklenir ve anahtarın rolüyle sınırlıdır:

```bash
curl -H "X-API-Key: nabs_xxx" http://localhost:8000/api/v1/assets
```

Etkileşimli API dokümanı: `/api/docs` (OpenAPI şeması `/api/openapi.json`). Dashboard'u tek çağrıyla besleyen özet uç: `GET /api/v1/dashboard/summary`.

### Lokal geliştirme
```bash
cd backend
pip install -r requirements.txt
export APP_ENV=development JWT_SECRET=dev SFTPGO_WEBHOOK_SECRET=dev \
  NABS_GIT_REPO_PATH=/tmp/nabs_git DATABASE_URL=sqlite:///./nabs_dev.db
python -m app.cli create-admin admin 'GüçlüParola1!'
uvicorn app.main:app --reload          # http://localhost:8000

cd ../frontend
npm install && npm run dev             # http://localhost:5173
```

### Testler ve yük testi
```bash
cd backend && python -m pytest tests/ -v      # 70 test
pip install locust && locust -f loadtest/locustfile.py --host http://localhost:8000
```

### MFA etkinleştirme
```bash
curl -X POST http://localhost:8000/api/v1/auth/mfa/enroll -H "Authorization: Bearer $TOKEN"
# dönen otpauth_uri'yi authenticator uygulamasına ekleyin;
# sonraki girişlerde form'a "otp" alanı ekleyin.
```

## Önemli API uçları
`POST /auth/token` (JWT, opsiyonel LDAP/OTP) · `POST /webhook/sftpgo` (HMAC) · `POST /discovery/scan` · `GET /reports/risk.pdf` · `POST /ai/chat` · `POST /ai/index-benchmark` (CIS RAG) · `POST /ai/advisories/{id}/generate-remediation` (yalnızca PENDING_APPROVAL'a yazar) · `GET /ai/assets/{id}/summarize-change` · `POST /remediations/{id}/transition` (state machine) · `GET /metrics` (Prometheus)

## Üretim notları
Secret'ları `.env` yerine Vault/KMS'ten verin (Spec Bölüm 10 notu). `rag_chunks` için Postgres'te pgvector kolonu ekleyin (init.sql içindeki yorum). Git deposu volume'unu şifreli diske koyun ve `mirror` remote tanımlayın (15 dk'da bir otomatik push). `DATA_RETENTION_DAYS` penceresini hukuk/uyum onayıyla kesinleştirin (Bölüm 12.3).
