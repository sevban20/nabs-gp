# NABS-GP — Üretim Kurulum ve İşletim Rehberi

Bu doküman NABS-GP'nin üretim (ya da üretim-benzeri test) ortamına Docker Compose ile kurulumunu, sertleştirilmesini, doğrulanmasını ve işletimini adım adım anlatır.

> Sürüm: 1.1.0 · Hedef kitle: DevOps / Sistem & Ağ Yöneticileri

---

## 1. Mimari özeti

Platform, ayrık ve olay güdümlü mikroservislerden oluşur:

| Servis | İmaj / kaynak | Görev | Varsayılan port |
|---|---|---|---|
| `nabs-db` | postgres:16-alpine | Ana veri deposu (pgvector) | 5432 |
| `nabs-redis` | redis:7-alpine | Celery broker/result | 6379 |
| `nabs-core-api` | ./backend | FastAPI API | 8000 |
| `celery-worker-high` | ./backend | Async görevler (yedek, tarama, drift, L2) | — |
| `celery-beat` | ./backend | Zamanlanmış görevler | — |
| `nabs-dashboard` | ./frontend (nginx) | React GUI + /api proxy | 5173 |
| `sftpgo` | drakkan/sftpgo | Pasif (air-gapped) yedek girişi | 2022, 8080 |
| **Opsiyonel** | | | |
| `caddy` | caddy:2 | TLS terminasyonu (HTTPS) | 80, 443 |
| `prometheus` / `grafana` | — | Observability | 9090 / 3000 |
| Harici `ollama` | ollama (native/ayrı) | Yerel LLM (AI özellikleri) | 11434 |
| Harici `vault` | HashiCorp Vault | Bootstrap secret'ları | 8200 |

Kalıcı veriler (Docker volume): `postgres_data`, `git_repository_storage` (config geçmişi — **tek kopya, mutlaka yedekleyin**), `sftpgo_data`, `sftpgo_uploads`, `tls_certs`.

---

## 2. Önkoşullar

- Linux sunucu (Ubuntu 22.04+ önerilir), 4 vCPU / 8 GB RAM (5.000 düğüm hedefi için 8 vCPU / 16 GB).
- Docker Engine 24+ ve Docker Compose v2.
- Config depolama volume'u için **şifreli blok cihaz** (LUKS vb.) — config'ler sanitize edilse de topoloji/ACL verisi hassastır.
- Dışa açılacaksa bir DNS/FQDN (TLS için) ve 443 erişimi.
- Yönetilen cihazlara SSH (22) ve/veya SNMP (161) erişimi olan bir ağ konumu.
- (Opsiyonel) HashiCorp Vault, yerel Ollama sunucusu, LDAP/AD.

---

## 3. Kurulum

### 3.1 Sihirbaz ile (önerilen)
Arşivi açtıktan sonra tek komut — gerekli soruları sorup `.env`'i üretir, secret'ları oluşturur, seçtiğiniz overlay'lerle (Vault/TLS/observability) stack'i kurar, admin'i oluşturur ve sağlık kontrolü yapar:
```bash
./install.sh
```
Sihirbazın sorduğu başlıklar: alan adı (FQDN/localhost), secret otomatik üretimi, secret backend (.env / gömülü Vault), TLS (yok / otomatik HTTPS / sonra yükle), observability, Ollama adresi, admin kullanıcı+parola. Enter ile varsayılanlar kabul edilir. Bitince erişim URL'si ve (ürettiyse) admin parolası + Vault notları ekrana yazılır.

### 3.2 Manuel (özet)
```bash
cp .env.example .env
python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"   # NABS_MASTER_KEY
# .env içindeki zorunlu alanları doldur (Bölüm 4)
docker compose up -d --build
docker exec -it nabs-api python -m app.cli create-admin admin '<güçlü-parola>'
curl -s http://localhost:8000/health
```

GUI: `http://localhost:5173` (TLS ile `https://<NABS_DOMAIN>`). Üretim için sertleştirme (Bölüm 6) şart.

---

## 4. Yapılandırma (.env)

`.env.example`'ı kopyalayıp doldurun. **Zorunlu** ve önemli alanlar:

### 4.1 Zorunlu secret'lar (fail-closed — eksikse servis açılmaz)
```ini
APP_ENV=production
# 44 karakterlik base64 (32 bayt). ÜRET ve GÜVENLE SAKLA — değişirse eski şifreli parolalar okunamaz:
NABS_MASTER_KEY=<python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())">
JWT_SECRET=<uzun-rastgele-değer>
SFTPGO_WEBHOOK_SECRET=<uzun-rastgele-değer>
```

### 4.2 Veritabanı & Redis
```ini
POSTGRES_USER=nabs_admin
POSTGRES_PASSWORD=<güçlü-parola>
POSTGRES_DB=nabs_governance
DATABASE_URL=postgresql://nabs_admin:<güçlü-parola>@nabs-db:5432/nabs_governance
REDIS_URL=redis://nabs-redis:6379/0
```

### 4.3 Ağ / erişim
```ini
# Dashboard'un gerçek origin'i (TLS arkasında https). Birden çok için virgülle ayır.
CORS_ORIGINS=https://nabs.sirket.local
# TLS (docker-compose.tls.yml) kullanacaksan:
NABS_DOMAIN=nabs.sirket.local
```

### 4.4 Opsiyonel bileşenler
```ini
# Yerel LLM (AI özellikleri). Yoksa AI uçları 503 döner, uygulama çökmez.
OLLAMA_ENDPOINT=http://host.docker.internal:11434/api/generate
OLLAMA_MODEL=llama3:8b-instruct

# Vault (bootstrap secret'ları). Tanımlıysa NABS_MASTER_KEY/JWT/SFTP oradan okunur:
# VAULT_ADDR=https://vault.corp:8200
# VAULT_TOKEN=...            (ya da VAULT_ROLE_ID + VAULT_SECRET_ID)
# VAULT_KV_MOUNT=secret
# VAULT_SECRET_PATH=nabs-gp

# Grafana admin parolası (observability stack):
GF_SECURITY_ADMIN_PASSWORD=<güçlü-parola>
```

> **Not:** Bildirim webhook'ları (Slack/Teams/Syslog), LDAP, veri saklama süreleri, login rate-limit ve drift önemi artık `.env` yerine **GUI → Ayarlar** panelinden yönetilir (DB'de tutulur, canlı etki eder). `.env`'e yazarsanız da geçerlidir (öncelik: DB override → env → varsayılan).

---

## 5. Kurulum adımları (detaylı)

1. **Kod ve .env:** Depoyu klonlayın, `.env`'i doldurun (Bölüm 4).
2. **Config volume'unu şifreli diske yerleştirin.** `git_repository_storage` için host üzerinde şifreli bir mount hazırlayın ve gerekiyorsa compose'da bind-mount'a çevirin.
3. **Ayağa kaldırın:** `docker compose up -d --build`. İlk açılışta DB şeması otomatik oluşur ve migration'lar uygulanır (Alembic'e gerek yoktur; şema `db/init.sql` + startup migrator ile gelir).
4. **İlk admin:** `docker exec -it nabs-api python -m app.cli create-admin admin '<parola>'`.
5. **Sağlık kontrolü:** `curl http://localhost:8000/health` → `{"status":"ok",...}`.
6. **Giriş:** GUI'de admin ile oturum açın.

---

## 6. Üretim sertleştirme (deploy'dan önce ZORUNLU)

### 6.1 TLS (HTTPS)
İki seçenek:

**A) Otomatik HTTPS (Let's Encrypt) — herkese açık FQDN varsa:**
```bash
NABS_DOMAIN=nabs.sirket.local \
  docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d
```

**B) Kurumsal/iç CA sertifikası — GUI'den yükleme:**
`deploy/Caddyfile` yerine `deploy/Caddyfile.uploaded`'ı bağlayın, ardından **GUI → Ayarlar → Sistem → Web Sunucu TLS Sertifikası** kartından PEM cert + private key yükleyin. Backend doğrular (anahtar-sertifika eşleşmesi, süre), paylaşımlı volume'a 0600/0644 izinle yazar; Caddy dosya değişince otomatik yeniler.

TLS'i açtıktan sonra `.env`'de `CORS_ORIGINS=https://<NABS_DOMAIN>` yapın ve dashboard'un 5173 port yayınını (docker-compose.yml) kaldırıp yalnızca Caddy'nin 443'ünü dışa açın.

### 6.2 Secret backend (Vault — önerilir)
Bootstrap secret'ları `.env` yerine Vault'ta tutulabilir. İki seçenek:

**A) Kendi Vault'unuz (varsa):** `.env`'e `VAULT_ADDR` + token (ya da AppRole) ekleyin ve secret'ları Vault KV v2'ye yazın (`VAULT_SECRET_PATH` altında `NABS_MASTER_KEY`, `JWT_SECRET`, `SFTPGO_WEBHOOK_SECRET`).

**B) Gömülü Vault (kendi Vault'unuz yoksa):** Kalıcı depolamalı, üretim-yetkin tek düğümlü Vault stack'e opsiyonel overlay olarak eklenir:
```bash
# 1) Yalnızca Vault'u başlat
docker compose -f docker-compose.yml -f docker-compose.vault.yml up -d nabs-vault
# 2) İlk kurulum: init + unseal + KV v2 + secret yazma + app token
./scripts/vault_init.sh
#    -> unseal anahtarı + root token 'vault-init.secret'e yazılır (GÜVENLE SAKLAYIN, taşıyın)
#    -> ekrandaki VAULT_ADDR / VAULT_TOKEN satırlarını .env'e ekleyin
# 3) Tüm stack'i başlat
docker compose -f docker-compose.yml -f docker-compose.vault.yml up -d
```
> **Önemli — unseal:** Vault her yeniden başlatıldığında *sealed* (kilitli) gelir ve açılması gerekir: `./scripts/vault_unseal.sh`. Bu manuel adımı kaldırmak için üretimde **otomatik unseal** yapılandırın (config.hcl'e cloud KMS / transit `seal` bloğu). `vault-init.secret` dosyasını kaybederseniz Vault verisine (ve şifreli her şeye) erişemezsiniz.

Her iki durumda doğrulama: **GUI → Ayarlar → Sistem → Secret Kaynağı** kartı her secret'ın kaynağını (vault/env) gösterir. Vault tanımlı ama erişilemezse (ör. sealed) platform **fail-closed** davranır — yanlış anahtarla açılmaz.

### 6.3 Diğer
- Konteynerler zaten **non-root** (`appuser`, uid 10001) çalışır.
- Postgres/Redis portlarını (5432/6379) dış dünyaya kapatın (yalnızca iç ağ).
- Güçlü, benzersiz parolalar; `create-admin` sonrası varsayılan hesap yok.
- MFA'yı kritik hesaplar için etkinleştirin (GUI → Ayarlar/Yönetim → MFA).

---

## 7. Kurulum sonrası doğrulama (checklist)

GUI → Ayarlar → **Sistem Durumu & Testler** ve genel akış:

- [ ] `/health` 200 dönüyor.
- [ ] Admin ile giriş yapılabiliyor; **Yönetim**'de kullanıcı oluştur/rol ata/pasifleştir çalışıyor.
- [ ] **Secret Kaynağı:** tüm bootstrap secret'ları "ayarlı" (vault ya da env).
- [ ] **TLS durumu:** `https://<NABS_DOMAIN>` sertifikası geçerli, makul gün kaldı.
- [ ] **LDAP testi** (kullanıyorsanız): bağlantı/bind başarılı.
- [ ] Bir test cihazı ekleyip **Yedekle** → İşlem Geçmişi'nde "başarılı"; **Config** ekranında içerik görünüyor.
- [ ] **Keşif** (tarama / L2 topla) ve **Ağ Haritası** çalışıyor.
- [ ] (AI kullanılacaksa) Chat sekmesinde LLM durumu yeşil.
- [ ] Grafana (opsiyonel) dashboard'ları veri gösteriyor.

---

## 8. Observability (opsiyonel)

```bash
docker compose -f docker-compose.yml -f docker-compose.observability.yml up -d
```
- Prometheus: `:9090` — API, Celery, Redis, Postgres metrikleri + `alert_rules.yml`.
- Grafana: `:3000` — "NABS-GP" klasöründe hazır 3 dashboard (API, Platform, Operasyon). İlk giriş: `admin` / `GF_SECURITY_ADMIN_PASSWORD` (ilk açılışta uygulanır).
- İş metrikleri `/metrics` altında: toplam/up/down cihaz, yedek başarı/hata, drift, açık bulgular.

---

## 9. Yedekleme & Felaket Kurtarma (DR)

- **Config deposu (kritik):** `git_repository_storage` her cihazın konfigürasyon geçmişinin tek kopyasıdır. `celery-beat` 15 dakikada bir `mirror` remote'una push eder — repoya bir `mirror` remote tanımlayın (iç Git sunucusu / object storage).
- **PostgreSQL:** `scripts/backup_db.sh` (pg_dump -Fc) — cron ile çalıştırın; `DB_BACKUP_RETENTION_DAYS` kadar saklar. Yedekte de parolalar uygulama katmanında şifreli kalır.
- **Veri saklama:** `DATA_RETENTION_DAYS` (GUI/Ayarlar) süresinden eski backup geçmişi ve çözülmüş bulgular günlük `purge_expired_records` göreviyle silinir.
- **Geri yükleme provası:** Düzenli olarak pg dump'ı boş bir ortama geri yükleyip config mirror'ından repoyu klonlayarak DR tatbikatı yapın.

---

## 10. Yükseltme (upgrade)

```bash
git pull
docker compose build
docker compose up -d
```
Şema değişiklikleri startup migrator ile otomatik uygulanır (mevcut tablolara eksik kolonlar eklenir). Büyük sürümlerde önce DB yedeği alın. Kesintisiz istenirse API/worker'ları sırayla yeniden başlatın.

---

## 11. Sorun giderme

| Belirti | Olası neden / çözüm |
|---|---|
| API açılmıyor, log'da `NABS_MASTER_KEY is not set` | `.env`'de master key boş. Üretip yazın, yeniden başlatın (Bölüm 4.1). |
| Kimlik bilgisi eklerken 503 "Şifreleme yapılandırması eksik" | Aynı sebep; master key eksik. |
| AI Chat 503 / "Ollama erişilemez" | Yerel LLM çalışmıyor. Ollama'yı ayrı çalıştırın (`ollama serve` + model pull) veya AI'yı kullanmayın — diğer özellikler etkilenmez. |
| Yedek "kuyrukta" kalıyor, ilerlemiyor | `celery-worker-high` çalışmıyor. `docker compose ps` ile kontrol edin. |
| Yedek "hata" (FAILED) | İşlem Geçmişi'nde hata metnine bakın: SSH erişimi/kimlik bilgisi/platform. |
| Config ekranı boş | O cihazdan henüz **başarılı** yedek yok. |
| GUI 502/CORS hatası | `CORS_ORIGINS` yanlış ya da API konteyneri ayakta değil; `docker logs nabs-api`. |
| Vault hatası açılışta | Vault tanımlı ama erişilemiyor (fail-closed). Vault'u düzeltin ya da `VAULT_*`'ı kaldırıp env'e dönün. |
| TLS sertifikası yüklenmiyor | Cert-key eşleşmiyor ya da süresi dolmuş (400). Doğru fullchain + key kullanın. |

İz sürme: her yanıt bir `request_id` taşır; hata loglarında `docker compose logs | grep <request_id>` ile tam izi bulabilirsiniz.

---

## 12. Bilinen üretim açık maddeleri (spec Bölüm 15)

Bunlar test ortamı için engel değildir; tam production sign-off öncesi ele alınmalıdır:
- Alembic tabanlı migration'a geçiş (şu an hafif startup migrator).
- 5.000 düğüm yük testi (`loadtest/locustfile.py`).
- OWASP penetrasyon testi.
- Veri saklama pencerelerinin hukuk/uyum (KVKK/GDPR) onayı.
- Cihaza otomatik yazma (write-back) bileşeni bilinçli olarak kapsam dışıdır (onaysız yazma yok ilkesi).
