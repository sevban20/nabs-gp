# NABS-GP Proje İnceleme, Eksiklik ve Geliştirme Raporu

**Proje:** NABS-GP (Network Asset, Backup & Security Governance Platform)  
**Sürüm:** v1.1.0  
**Tarih:** 24 Ağustos 2026  
**Değerlendirme Alanları:** Mimari, Güvenlik, Veri Yönetimi, Kod Kalitesi, AI/RAG Entegrasyonu, Performans ve Operasyonel Hazırlık.

---

## 1. YÖNETİCİ ÖZETİ (EXECUTIVE SUMMARY)

NABS-GP; heterojen kurumsal ağlarda konfigürasyon yedekleme, sürümleme, güvenlik denetimi, topoloji keşfi, risk skorlama ve yapay zeka destekli yönetişimi bir araya getiren **yüksek kaliteli, modüler ve production-ready** bir mikroservis platformudur. 

Proje, özellikle **Fail-Closed güvenlik yaklaşımı**, **onaysız cihaz müdahalesini engelleyen read-only çekirdek tasarımı**, **yerel LLM ile veri gizliliği** ve **çok katmanlı keşif motoru** ile kurumsal standartların üzerinde bir başarı sergilemektedir. Ancak veritabanı migration süreçleri, onaylı cihaza yazma (write-back) mekanizması, gerçek cihaz emülasyon testleri ve frontend durum yönetimi konularında geliştirmeye açık alanlar tespit edilmiştir.

---

## 2. GÜÇLÜ VE BAŞARILI YÖNLER (PROS / İYİ YÖNLER)

### 🟢 2.1. Güvenlik ve Mimarı Tasarım İlkeleri
1. **Fail-Closed Güvenlik Yaklaşımı:** `NABS_MASTER_KEY` veya `JWT_SECRET` gibi kritik sırların bulunmadığı veya Vault erişiminin sağlanan yapılandırmada başarısız olduğu durumlarda sistem kendisini korumaya alarak başlatmayı reddeder (Fail-Closed).
2. **Onaysız Cihaza-Yazma Engeli (Read-Only Core):** Sistemdeki temel SSH sürücüleri varsayılan olarak salt-okunur komutlar (`show running-config`, `display current-configuration`, `/export` vb.) çalıştırır. İyileştirme kodları kesinlikle otomatize bir şekilde cihazlara push edilmez.
3. **Çok-Vendörlü Hassas Veri Maskeleme (`SecretSanitizer`):** Konfigürasyonlar Git deposuna veya veritabanına kaydedilmeden önce bellek seviyesinde regex tabanlı maskeleme motorundan geçer. Cisco type-5/7, Fortinet enc, MikroTik PSK ve OpenWrt UCI parolaları şifreli alanlara yazılmadan önce `****` ile gizlenir.
4. **Dört-Göz (Four-Eyes) İlkesi & State Machine:** Remediation (düzeltme) onay sürecinde talebi oluşturan operatör/AI ile onaylayan yetkili (Approver/Admin) aynı olamaz. State machine (`PENDING_APPROVAL` ➔ `APPROVED` ➔ `STAGED`) sayesinde yetkisiz değişikliklerin önüne geçilir.

### 🟢 2.2. Katmanlı Keşif ve Topoloji Motoru
1. **Multi-Signal Discovery:** Yalnızca SNMP'ye bağımlı kalmaz. TCP Probe canlılık kontrolünden sonra SNMP `sysDescr` ve SSH Banner fingerprinting ile cihaz tanıma yapılır.
2. **L2/L3 Uç Cihaz Keşfi (ARP + MAC + OUI):** Ağ cihazlarından `show ip arp` ve `show mac address-table` verilerini toplayarak MAC adresi OUI kataloğundan (~50 üretici) uç cihazları (printer, IP telefon, server, VMware vb.) tespit eder ve envantere aday gösterir.
3. **Bağımlılıksız Canlı Topoloji:** Üçüncü taraf JS kütüphanesi kullanmadan geliştirişmiş, hafif ve yüksek performanslı SVG Force-Directed Graph ile canlı ağ haritası sunar.

### 🟢 2.3. Veri Mahremiyeti ve Yerel AI (Ollama + RAG)
1. **Gömülü Olmayan (Decoupled) LLM:** AI katmanı platformdan bağımsızdır (`llama3:8b-instruct` & `nomic-embed-text`). Ağ konfigürasyonları veya IP bilgileri asla buluta sızmaz.
2. **Zirve Dayanıklılık (503 Fallback):** Ollama servisi kapalı veya erişilemez olduğunda sistem çökmez; AI uç noktaları açıklayıcı 503 hatası verir ve core yedekleme/güvenlik işlevleri aksamadan çalışır.
3. **pgvector RAG:** CIS Benchmark dokümanları veritabanında vektörleştirilerek mevzuata uygun Chat-with-Network olanağı sağlar.

### 🟢 2.4. DevSecOps ve Operasyonel Kolaylıklar
1. **Hızlı Kurulum Sihirbazı (`install.sh`):** Alan adı, secret üretimi, Vault/TLS/Observability ve Ollama yapılandırmasını interaktif sorularla yönetip `.env` oluşturan yetkin bir kurulum betiği mevcut.
2. **Konteyner Güvenliği:** Konteynerler `appuser` (uid 10001) non-root kullanıcısı ile çalışır.
3. **Grafana & Prometheus Entegrasyonu:** Tam teşekküllü `/metrics` uç noktası ve hazır Grafana dashboard şablonları sunar.

---

## 3. ZAYIF, EKSİK VE RİSKLİ YÖNLER (CONS / KÖTÜ VE EKSİK YÖNLER)

### 🔴 3.1. Veritabanı Migration Yönetimi (Alembic Eksikliği)
* **Mevcut Durum:** `backend/app/core/migrations.py` dosyası içinde manuel ve hafif bir `ALTER TABLE` döngüsü bulunmaktadır.
* **Risk/Eksiklik:** SQLAlchemy `Base.metadata.create_all()` yeni tabloları oluşturur ancak mevcut tablolara yeni kolon eklendiğinde basit alter çalıştırır. Kolon tipi değişiklikleri, indeks güncellemeleri, kolon silme (drop) veya veritabanı rollback işlemleri için Alembic kullanılmamaktadır. Üretim ortamında veritabanı şema evrimi risk altındadır.

### 🔴 3.2. Cihaz İyileştirme (Write-Back) Seçeneğinin Olmaması
* **Mevcut Durum:** Onaylanan remediation kodları `STAGED` durumunda kalmaktadır. Cihaza yazma bileşeni bilinçli olarak kapsam dışı bırakılmıştır.
* **Risk/Eksiklik:** Güvenlik açısından doğru bir karar olsa da, kurumsal NCCM (Network Configuration and Change Management) ürünlerinde "Onaylanmış Değişikliği Zamanlanmış Olarak Cihaza Uygula (Push Configuration)" seçeneği aranmaktadır. Operatörün komutları elle kopyalayıp SSH terminaline yapıştırması gerekmektedir.

### 🔴 3.3. Test Kapsamı ve Emülasyon Eksikliği
* **Mevcut Durum:** `backend/tests/` altında 33 test dosyası mevcuttur (Mock ağırlıklı unit/integration testler).
* **Risk/Eksiklik:** Gerçek ağ cihazı davranışlarını simüle eden sanal ağ ortamları (Containerlab, GNS3, Cisco VIRL) ile entegre e2e (end-to-end) entegrasyon test pipeline'ı yoktur. Sürücülerin gerçek CLI çıktı varyasyonlarındaki başarısı yalnızca mock metinlerle doğrulanmaktadır.

### 🔴 3.4. AI / LLM Çağrılarında Kuyruk Darboğazı Riski
* **Mevcut Durum:** Celery worker'ları hem SSH yedekleme hem keşif hem de LLM RAG/summarize görevlerini ortak kuyruklardan almaktadır.
* **Risk/Eksiklik:** Ağır bir LLM sorgusu veya RAG indeksleme işlemi sırasında worker CPU/bellek kaynaklarını tüketerek kritik SSH yedekleme veya erişilebilirlik taramalarının gecikmesine yol açabilir.

### 🔴 3.5. Frontend State Management ve Hata Yakalama
* **Mevcut Durum:** React dashboard'unda veriler `useEffect` ve `fetch` çağrıları ile yönetilmektedir.
* **Risk/Eksiklik:** React Query (TanStack Query) veya SWR gibi modern asenkron veri yönetimi kullanılmadığı için önbellekleme (caching), arka plan yenileme (background refetching) ve optimistic UI güncellemeleri sınırlıdır.

---

## 4. GELİŞTİRİLMESİ GEREKEN YÖNLER VE ÖNERİLER (ROADMAP)

### 🚀 4.1. Kısa Vadeli İyileştirmeler (1-3 Ay)

1. **Alembic Veritabanı Migrasyon Entegrasyonu:**
   * `core/migrations.py` yerine resmi `alembic` yapılandırması eklenmeli. Tüm şema değişiklikleri versiyonlanmış migration script'leri (`alembic revision --autogenerate`) ile yürütülmeli.
2. **Ayrıştırılmış Celery Kuyrukları (Queue Separation):**
   * LLM ve AI görevleri için ayrı bir Celery kuyruğu (`ai_queue`) ve ayrı worker konteynerleri (`celery-worker-ai`) tanımlanmalı. Ağ I/O işleri (`backup_queue`, `discovery_queue`) AI yükünden tamamen izole edilmeli.
3. **Frontend React Query (TanStack Query) Geçişi:**
   * API istekleri caching, retry logic ve polling yönetimi için TanStack Query mimarisine taşınmalı.

---

### 🚀 4.2. Orta Vadeli İyileştirmeler (3-6 Ay)

1. **İsteğe Bağlı & Denetimli Write-Back (Cihaza Konfigürasyon Push):**
   * Admin konfigürasyonu ile aktif edilebilen, yalnızca `STAGED` durumdaki onaylı remediation'ları çalıştıran bir **Write-Back Engine** eklenmeli.
   * Müdahale öncesi otomatik rollback snapshot'ı alınmalı ve işlem sonrası config tekrar kontrol edilmelidir.
2. **Jump-Host / Bastion & SSH Proxy Desteği:**
   * Karmaşık ağlarda cihazlara doğrudan erisilemediğinde SSH Bastion / Jump-Host üzerinden tünelleme desteği eklenmeli.
3. **Containerlab ile Otomatik E2E CI/CD Testleri:**
   * GitHub Actions veya GitLab CI süreçlerine Arista cEOS, FRRouting veya VyOS imajlarıyla çalışan Containerlab entegre edilerek sürücüler canlı CLI ortamında test edilmeli.

---

### 🚀 4.3. Uzun Vadeli İyileştirmeler (6+ Ay)

1. **Multi-Tenancy ve Kurumsal Organizasyon Desteği:**
   * Farklı müşteri veya departmanların ağ envanterlerini izole bir şekilde yönetebilmesi için Multi-Tenant veritabanı ve RBAC mimarisi.
2. **SAML 2.0 / OpenID Connect (OIDC) SSO:**
   * Okta, Keycloak, Azure AD ile kurumsal Single Sign-On entegrasyonu.
3. **Yüksek Erişilebilirlik (HA) Şablonları:**
   * Redis Sentinel / Cluster ve PostgreSQL Patroni şablonları içeren `docker-compose.ha.yml` mimarisinin eklenmesi.

---

## 5. GENEL DEĞERLENDİRME TABLOSU

| Değerlendirme Kriteri | Puan (10 Üzerinden) | AÇIKLAMA |
|---|---|---|
| **Güvenlik Mimarisi & Şifreleme** | 9.5 / 10 | Fail-closed yapı, AES-256 Vault, SecretSanitizer, Dört-göz onay akışı son derece başarılı. |
| **Kod Kalitesi ve Modülerlik** | 9.0 / 10 | FastAPI async mimari, Pydantic v2 modelleri ve katmanlı servis dizaynı temiz. |
| **İşlevsellik & Özellik Zenginliği** | 8.8 / 10 | L2/L3 keşif, Git diff, RAG AI, CVE entegrasyonu ve canlı topoloji ile çok zengin. |
| **Veri Yönetimi & Migrasyon** | 7.0 / 10 | Alembic yerine hafif script kullanılması üretim riski taşıyor. |
| **Test Kapsamı & Doğrulama** | 7.5 / 10 | Mock testleri iyi ancak canlı emülatör (Containerlab) entegrasyonu eksik. |
| **Kullanıcı Deneyimi (GUI)** | 8.5 / 10 | NMS tarzı karanlık/aydınlık tema ve SVG topoloji haritası harika. State management geliştirilebilir. |
| **GENEL PROJE PUANI** | **8.4 / 10** | **Üretim Seviyesine Çok Yakın / Kurumsal Standartlarda Yüksek Kalite** |

---
*Rapor Sonu — NABS-GP Teknik İnceleme ve Değerlendirme Komitesi*
