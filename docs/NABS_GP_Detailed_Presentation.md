# NABS-GP (Network Asset, Backup & Security Governance Platform)
## Detaylı Proje Sunumu ve Teknik İnceleme Raporu

---

## 📋 İÇİNDEKİLER

1. [Slayt 1: Başlık ve Yönetici Özeti](#slayt-1-başlık-ve-yönetici-özeti)
2. [Slayt 2: Sektörel Problemler ve İhtiyaç Analizi](#slayt-2-sektörel-problemler-ve-i̇htiyaç-analizi)
3. [Slayt 3: NABS-GP Değer Önermesi ve Ana Yetenekler](#slayt-3-nabs-gp-değer-önermesi-ve-ana-yetenekler)
4. [Slayt 4: Mikroservis Mimarisi ve Sistem Topolojisi](#slayt-4-mikroservis-mimarisi-ve-sistem-topolojisi)
5. [Slayt 5: Konfigürasyon Yedekleme (Aktif & Pasif) ve Git Sürüm Kontrolü](#slayt-5-konfigürasyon-yedekleme-aktif--pasif-ve-git-sürüm-kontrolü)
6. [Slayt 6: Katmanlı Keşif Motoru (L2/L3) ve Envanter Yönetimi](#slayt-6-katmanlı-keşif-motoru-l2l3-ve-envanter-yönetimi)
7. [Slayt 7: Canlı Topoloji Haritası ve Ağ Görselleştirme](#slayt-7-canlı-topoloji-haritası-ve-ağ-görselleştirme)
8. [Slayt 8: Config Drift ve Zamanlanmış Uyumluluk Tarama](#slayt-8-config-drift-ve-zamanlanmış-uyumluluk-tarama)
9. [Slayt 9: Çok Katmanlı Güvenlik Denetimi & CVE/CPE Eşleşmesi](#slayt-9-çok-katmanlı-güvenlik-denetimi--cvecpe-eşleşmesi)
10. [Slayt 10: Yerel AI (Ollama) & pgvector RAG Katmanı](#slayt-10-yerel-ai-ollama--pgvector-rag-katmanı)
11. [Slayt 11: Değişiklik Yönetişimi & Remediation Onay Akışı](#slayt-11-değişiklik-yönetişimi--remediation-onay-akışı)
12. [Slayt 12: Güvenlik Mimarisi, Şifreleme ve Hassas Veri Koruma](#slayt-12-güvenlik-mimarisi-şifreleme-ve-hassas-veri-koruma)
13. [Slayt 13: Desteklenen Cihaz Ekosistemi ve Protokol Entegrasyonları](#slayt-13-desteklenen-cihaz-ekosistemi-ve-protokol-entegrasyonları)
14. [Slayt 14: Gözlemlenebilirlik (Observability) ve Kurumsal Entegrasyonlar](#slayt-14-gözlemlenebilirlik-observability-ve-kurumsal-entegrasyonlar)
15. [Slayt 15: Sistem Yönetimi, TLS ve Sertifika Operasyonları](#slayt-15-sistem-yönetimi-tls-ve-sertifika-operasyonları)
16. [Slayt 16: Dağıtım (Deployment), Kurulum Sihirbazı ve Ölçeklenebilirlik](#slayt-16-dağıtım-deployment-kurulum-sihirbazı-ve-ölçeklenebilirlik)
17. [Slayt 17: Proje Faz Tamamlanma Durumu ve Yol Haritası](#slayt-17-proje-faz-tamamlanma-durumu-ve-yol-haritası)
18. [Slayt 18: Özet ve Sonuç](#slayt-18-özet-ve-sonuç)

---

## SLAYT 1: BAŞLIK VE YÖNETİCİ ÖZETİ

### **NABS-GP — Network Asset, Backup & Security Governance Platform**
*Heterojen ve Çok Vendörlü Kurumsal Ağlar İçin Yeni Nesil Yönetişim, Otomasyon ve Güvenlik Platformu*

* **Sürüm:** v1.1.0 (Faz 1-5 Tam Kapsam + Faz 6 GUI Entegrasyonu)
* **Mimari Yaklaşım:** Ayrık (Decoupled), Olay-Güdümlü (Event-Driven) Mikroservis Topolojisi
* **Temel Amaç:** Karmaşık ağ altyapılarında konfigürasyon yedekleme, sürümleme, güvenlik denetimi, risk skorlama, config drift tespiti ve yerel AI destekli iyileştirme yönetişimini tek bir platformda birleştirmek.

> **Geliştirme Felsefesi:** *Fail-Closed Güvenlik · Sıfır Onaysız Cihaza-Yazma (Read-Only Core) · Tam Veri Mahremiyeti (Yerel LLM) · Kesintisiz Gözlemlenebilirlik*

---

## SLAYT 2: SEKTOREL PROBLEMLER VE İHTİYAÇ ANALİZİ

### **Geleneksel Ağ Yönetimindeki Temel Zorluklar**

| Problem Alanı | Yaşanan Aksaklıklar ve Riskler | NABS-GP Çözümü |
|---|---|---|
| **Vendör Bağımlılığı & Silolar** | Cisco, Fortinet, Palo Alto, Juniper vb. farklı GUI/CLI araçlarının ayrı ayrı yönetilmesi. | Tek bir platform üzerinden 10+ vendör ve Linux (OpenWrt) desteği ile merkezi yönetim. |
| **Görünürlük Eksikliği** | Ağda çalışan ve kaydı olmayan (shadow device / unmanaged) cihazların varlığı. | Katmanlı keşif (TCP, SNMP, SSH) + LLDP/CDP + ARP/MAC/OUI L2 uç cihaz keşfi. |
| **Konfigürasyon Kayıpları** | Değişikliklerin kimin tarafından yapıldığının takip edilememesi, kurtarma süresinin (MTTR) uzaması. | Gömülü Git motoru ile anlık satır satır diff tespiti ve tek tıkla geçmişe dönük versiyon kıyası. |
| **Güvenlik & Uyum Açıkları** | Zayıf şifreleme, varsayılan parolalar, açık protokoller (Telnet, HTTP) ve CVE zafiyetleri. | CIS Benchmark tabanlı statik kurallar, YAML politikaları, NVD CVE eşleşmesi ve otomatik risk skorlama. |
| **Veri Sızıntısı Riski (Cloud AI)** | Ağ konfigürasyonlarının (IP düzeni, parola hash'leri) bulut bazlı LLM servislerine gönderilmesi. | Tamamen kurum içinde (On-Prem) çalışan yerel Ollama LLM + pgvector RAG entegrasyonu. |
| **Yetkisiz / Hatalı Müdahale** | Yanlış komutların cihazlara gönderilerek ağın çökmesi (Outage). | Strict "Dört-Göz" onay mekanizması. Onaylanmamış hiçbir değişiklik cihaza uygulanamaz. |

---

## SLAYT 3: NABS-GP DEĞER ÖNERMESİ VE ANA YETENEKLER

### **Platformun Sunduğu Temel Değerler**

1. **Merkezi Konfigürasyon Kasası & Git Sürümleme**
   * Tüm cihaz yapılandırmaları zamanlanmış veya tetiklemeli olarak çekilir, otomatik şifre/secret maskelemesinden geçirilerek Git reposunda versiyonlanır.
2. **Katmanlı Ağ Görünürlüğü ve Canlı Topoloji**
   * L2/L3 komşuluk ilişkileri (LLDP/CDP/ARP/MAC) taranarak SVG tabanlı dinamik ve etkileşimli ağ haritası oluşturulur.
3. **Zamanlanmış & Anlık Config Drift Tespiti**
   * Belirlenen "Golden (Referans) Config" ile mevcut yapılandırma sürekli kıyaslanır; sapmalar anında algılanarak alarm üretilir.
4. **Yerel Yapay Zeka (Chat-with-Network & RAG)**
   * Konfigürasyon değişikliklerinin doğal dilde özeti, CIS kıyaslamaları üzerinden chat asistanı ve otomatik remediation (iyileştirme) komut üretimi.
5. **Katı Yönetişim ve Dört-Göz Onay Akışı**
   * Yapay zeka veya operatör tarafından önerilen iyileştirme komutları approver/admin onayı olmadan asla işleme alınmaz (State Machine).

---

## SLAYT 4: MİKROSERVİS MİMARİSİ VE SİSTEM TOPOLOJİSİ

```
                     ┌─────────────────────────────────────────┐
                     │          KULLANICI & SİSTEMLER          │
                     └────────────────────┬────────────────────┘
                                          │ HTTPS
                                          ▼
                               ┌─────────────────────┐
                               │   Caddy 2 (TLS Proxy)│
                               └──────────┬──────────┘
                                          │
                   ┌──────────────────────┴──────────────────────┐
                   │                                             │
                   ▼                                             ▼
        ┌─────────────────────┐                       ┌─────────────────────┐
        │   nabs-dashboard    │                       │    nabs-core-api    │
        │   (React 18 + Nginx)│                       │   (FastAPI Async)   │
        └─────────────────────┘                       └──────────┬──────────┘
                                                                 │
      ┌──────────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────┐
      │                                                          │                                                          │
      ▼                                                          ▼                                                          ▼
┌──────────────┐                                        ┌─────────────────┐                                        ┌──────────────────┐
│ PostgreSQL 16│                                        │  Redis 7 Broker │                                        │ HashiCorp Vault  │
│  + pgvector  │                                        └────────┬────────┘                                        │   (Secret Mgr)   │
└──────────────┘                                                 │                                                 └──────────────────┘
      ▲                                                          ▼
      │                                                ┌──────────────────┐
      │                                                │  Celery Workers  │
      │                                                └────────┬─────────┘
      │                                                         │
      └─────────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────┐
                                                                │                                                          │
                                                                ▼                                                          ▼
                                                     ┌────────────────────┐                                     ┌──────────────────┐
                                                     │ Ağ Cihazları (SSH) │                                     │  Ollama (LLM)    │
                                                     └────────────────────┘                                     └──────────────────┘
```

### **Bileşen Detayları**
* **nabs-core-api:** Python 3.11 / FastAPI tabanlı, tamamen asenkron, stateless REST API katmanı. JWT authentication, RBAC yetkilendirme ve orkestrasyonu sağlar.
* **Celery Workers & Beat:** Ağ tarama, yedekleme (SSH Scrapli/Paramiko), keşi̇f, CVE senkronizasyonu ve bildirim gönderimi gibi ağır I/O işlemlerini arka planda asenkron yürütür.
* **PostgreSQL 16 + pgvector:** İlişkisel veriler, audit loglar, envanter ve AI RAG vektör gömmeleri (embeddings) için merkezi veritabanı.
* **Git Repository Volume:** Tüm konfigürasyon sürüm geçmişinin tutulduğu yerel Git deposu (off-host 15 dk'lık mirror yedeklemeli).
* **SFTPGo:** Air-gapped / pasif cihazlardan SFTP ile gelen yedekleri alan ve HMAC imzalı webhook ile API'ye bildiren pasif alma bileşeni.

---

## SLAYT 5: KONFİGÜRASYON YEDEKLEME (AKTİF & PASİF) VE GİT SÜRÜM KONTROLÜ

### **1. Aktif Yedekleme Akışı (SSH Scrapli / Paramiko)**
* **Orkestrasyon:** Celery Beat veya kullanıcı tetiklemesi ile başlatılır.
* **Bağlantı:** Scrapli driver'ları kullanılarak cihaza salt-okunur (read-only) SSH bağlantısı kurulur (`show running-config`, `display current-configuration`, `uci export` vb.).
* **Hassas Veri Maskeleme:** Ham konfigürasyon bellek üzerinde çok-vendörlü `SecretSanitizer` katmanından geçirilir (Cisco type-5/7, Fortinet enc, MikroTik PSK, OpenWrt UCI secrets maskelenir).
* **Git Commit:** Maskelenmiş metin Git deposuna yazılır. Sadece fark (diff) varsa yeni commit oluşturulur (`SUCCESS` status + commit hash DB'ye kaydedilir).

### **2. Pasif Yedekleme Akışı (Air-Gapped SFTPGo)**
* **Senaryo:** Dışarıdan SSH bağlantısına izin vermeyen veya izole bölgedeki cihazlar.
* **İşlem:** Cihaz konfigürasyonunu SFTPGo sunucusuna push eder. SFTPGo, ham gövde üzerinden **HMAC-SHA256** imzalı webhook tetikler.
* **Güvenlik:** API webhook'u doğrular, path-traversal engellemesi yapar, konfigürasyonu sanitize eder ve Git deposuna commit eder.

---

## SLAYT 6: KATMANLI KEŞİF MOTORU (L2/L3) VE ENVANTER YÖNETİMİ

NABS-GP, ağdaki tüm varlıkları tespit etmek için **çok katmanlı (multi-layered) bir keşif yaklaşımı** benimser:

```
[ CIDR Tarama ] ──► (1) TCP Live Check ──► (2) SNMP sysDescr ──► (3) SSH Banner Fingerprint
                                                                       │
                                                                       ▼
[ L2/L3 Topoloji Keşfi ] ◄── ARP & MAC Tablosu ◄── LLDP / CDP Tarama ──┘
```

1. **Katman 1 — Canlılık Tespiti:** Hedef CIDR aralığında TCP Probe ile aktif host'lar belirlenir.
2. **Katman 2 — SNMP & SSH Fingerprinting:** Cihazların üreticisi (Vendor) ve OS versiyonu SNMP `sysDescr` ve SSH Banner imzalarıyla tespit edilir (SNMP kapalı olsa bile SSH banner ile tanıma).
3. **Katman 3 — LLDP / CDP Komşuluk Keşfi:** Yönetilen cihazlardan komşuluk tabloları çekilerek ağdaki görünmeyen anahtar/yönlendiriciler çıkarılır.
4. **Katman 4 — L2 Uç Cihaz Keşfi (ARP + MAC + OUI):** Switch ve router'lardan `show ip arp` ve `show mac address-table` verileri toplanır. MAC adresinin ilk 3 oktetinden (OUI) cihaz üreticisi (~50 bilinen vendor) tahmin edilir. Uç cihazlar envantere aday gösterilir.

---

## SLAYT 7: CANLI TOPOLOJİ HARİTASI VE AĞ GÖRSELLEŞTİRME

### **Dinamik SVG Ağ Haritası Özellikleri**
* **Teknoloji:** Üçüncü taraf kütüphane bağımlılığı olmaksızın geliştirilmiş, hafif ve yüksek performanslı SVG Force-Directed Graph render motoru.
* **Görsel Durum İndikatörleri:**
  * **Düğüm Rengi:** Cihazın hesaplanan güvenlik risk skorunu yansıtır (Yeşil = Düşük Risk, Turuncu = Orta, Kırmızı = Yüksek/Kritik Risk).
  * **Kesikli Halka (Dashed Ring):** Cihazın erişilemez (Down) durumda olduğunu gösterir.
  * **Gri Düğümler:** Yalnızca komşuluk (LLDP/CDP) veya L2 taramasıyla keşfedilmiş, henüz NABS-GP envanterine eklenmemiş "Yönetilmeyen (Unmanaged)" cihazlar.
* **Interaktivite:** Düğümlere tıklandığında cihaz detay paneli, aktif uyarılar, son yedeklenme zamanı ve komşuluk bağları görüntülenir.

---

## SLAYT 8: CONFIG DRIFT VE ZAMANLANMIŞ UYUMLULUK TARAMA

### **Config Drift (Konfigürasyon Sapması) Yönetimi**

* **Golden Baseline (Referans Konfigürasyon):**
  * Admin veya yetkili operatör, bir cihazın bilinen stabil konfigürasyonunu "Baz Al (Baseline)" butonu veya API uç noktası (`POST /assets/{id}/baseline`) ile referans olarak sabitler.
* **Sapma Algılama Noktaları:**
  1. **Yedekleme Anında:** Her yeni yedek çekildiğinde veya SFTP ile geldiğinde mevcut yapılandırma Golden Baseline ile otomatik olarak `git diff` mantığında kıyaslanır.
  2. **Zamanlanmış Tarama (Hourly Sweep):** Saatlik çalışan `run_compliance_sweep` görevi, yeni bir yedek gelmese dahi tüm filoyu referans konfigürasyona karşı denetler.
* **Otomatik Alarm & İyileşme (Auto-Resolution):**
  * Sapma tespit edildiğinde cihaz `has_drift = True` olarak işaretlenir ve otomatik `CONFIG-DRIFT` güvenlik advisory'si açılır.
  * Cihaz konfigürasyonu tekrar referans duruma getirildiğinde açılan advisory **otomatik olarak kapatılır (RESOLVED)**.

---

## SLAYT 9: ÇOK KATMANLI GÜVENLİK DENETİMİ & CVE/CPE EŞLEŞMESİ

NABS-GP, alınan her konfigürasyonu 4 farklı güvenlik süzgecinden geçirir:

```
                             ┌────────────────────────┐
                             │ Gelen Konfigürasyon    │
                             └───────────┬────────────┘
                                         │
                                         ▼
                        ┌─────────────────────────────────┐
                        │ 1. Statik Kural Engine (Python) │
                        └────────────────┬────────────────┘
                                         │
                                         ▼
                        ┌─────────────────────────────────┐
                        │ 2. Esnek YAML Politika Engine   │
                        └────────────────┬────────────────┘
                                         │
                                         ▼
                        ┌─────────────────────────────────┐
                        │ 3. NVD CVE / CPE Eşleşme Engine │
                        └────────────────┬────────────────┘
                                         │
                                         ▼
                        ┌─────────────────────────────────┐
                        │ 4. Otomatik Risk Skorlama Engine│
                        └─────────────────────────────────┘
```

1. **Statik Kurallar:** Telnet kullanımı, zayıf SNMP topluluk isimleri (public/private), şifrelenmemiş enable parolaları, varsayılan HTTP yönetimi.
2. **YAML Politika Motoru:** `policies/` dizininde tanımlı özelleştirilebilir kurallar (örneğin NTP sunucu zorunluluğu, SSH timeout limitleri, banner metinleri).
3. **NVD CVE / CPE Senkronizasyonu:** Cihazın işletim sistemi ve versiyonu NVD (National Vulnerability Database) CPE formatına dönüştürülür ve güncel CVE veritabanı ile eşleştirilir.
4. **Dinamik Risk Skorlama:** Temsili Ağ Riski = $\sum (\text{Severity Weight} \times \text{Advisory Count})$. Cihazlar 0-100 arasında derecelendirilir.

---

## SLAYT 10: YEREL AI (OLLAMA) & PGVECTOR RAG KATMANI

### **Veri Mahremiyeti Odaklı Yerel Yapay Zeka Entegrasyonu**

* **Gömülü Olmayan (Decoupled) LLM Mimarisi:** Ollama mimarisi platforma gömülü değildir; ayrı bir konteyner veya harici sunucuda (GPU/CPU) çalışabilir (`llama3:8b-instruct` & `nomic-embed-text`).
* **Fail-Safe Tasarım:** LLM sunucusuna ulaşılamadığında sistem çökmez. AI uçları 503 Service Unavailable döner, GUI'de "LLM Erişilemez" rozeti gösterilir ve diğer tüm yedekleme/güvenlik işlevleri kesintisiz çalışmaya devam eder.

### **AI Kullanım Senaryoları**
1. **Chat-with-Network:** Doğal dilde ağ durumunu sorgulama ("Kritik riskli Cisco cihazlarım hangileri?", "BFP konfigürasyon standartlarımız nedir?").
2. **CIS Benchmark RAG (pgvector):** CIS güvenlik dokümanları vector embedding olarak PostgreSQL pgvector'e indekslenir. Sorular bu bilgi tabanı üzerinden yanıtlanır.
3. **Değişiklik Özeti (Change Summarization):** İki konfigürasyon arasındaki diff'i analiz ederek teknik olmayan yöneticiler için özet rapor üretme.
4. **Otomatik Remediation Üretimi:** Açılan güvenlik bulguları için cihaza özel düzeltme script'i hazırlama.

---

## SLAYT 11: DEĞİŞİKLİK YÖNETİŞİMİ & REMEDIATION ONAY AKIŞI

### **"Dört-Göz" İlkesi ve Onay State Machine**

NABS-GP, güvenlik ilkeleri gereği **otomatik olarak cihaza komut göndermez (No Unapproved Write-Back)**. Üretilen tüm iyileştirme kodları sıkı bir onay sürecine tabidir.

```
       [ Zafiyet Tespiti ] ──► [ AI Remediation Üretimi ]
                                        │
                                        ▼
                            [ PENDING_APPROVAL ] ◄── (Talep Oluşturuldu)
                                        │
                       ┌────────────────┴────────────────┐
                       │                                 │
                       ▼                                 ▼
              [ REJECTED / CANCELLED ]             [ APPROVED ] (Dört-Göz Kontrolü:
                                                         │      Onaylayan ≠ Talep Eden)
                                                         ▼
                                                    [ STAGED ] (Uygulamaya Hazır)
```

* **Dört-Göz (Four-Eyes) İlkesi:** Düzeltme talebini oluşturan (Operator/AI) ile talebi onaylayan (Approver/Admin) aynı kullanıcı olamaz.
* **Kritiklik Engeli:** CRITICAL ve HIGH seviyesindeki bulgular onay aşaması atlanarak doğrudan STAGED durumuna getirilemez.

---

## SLAYT 12: GÜVENLİK MİMARİSİ, ŞİFRELEME VE HASSAS VERİ KORUMA

### **Güvenlik Tasarım Kararları**

| Güvenlik Katmanı | Uygulama Mekanizması |
|---|---|
| **Fail-Closed Anahtar Yönetimi** | `NABS_MASTER_KEY` veya `JWT_SECRET` eksikse sistem üretim modunda başlamayı reddeder. |
| **Hassas Veri Kasası (Credentials Vault)** | SSH/SNMP parolaları ve private key'ler DB'de **AES-256-GCM** ile şifrelenmiş olarak saklanır. Master key HashiCorp Vault KV v2 veya güvenli env üzerinden beslenir. |
| **Secret Sanitizer (Maskeleme Engine)** | Konfigürasyonlar Git'e veya DB'ye kaydedilmeden önce tüm şifreler, enable secret'lar, PSK'ler ve hash'ler regex tabanlı maskeleme motorundan geçer. |
| **Kimlik Doğrulama & Yetkilendirme** | JWT (JSON Web Tokens), TOTP tabanlı MFA (Google/Microsoft Authenticator), LDAP / Active Directory entegrasyonu ve RBAC (Viewer, Operator, Approver, Admin). |
| **Değiştirilemez Audit İzleri (Append-Only Log)** | Sistemdeki tüm oturum açma, konfigürasyon değişikliği, onay ve ayar güncellemeleri silinemez append-only audit tablosuna kaydedilir. |

---

## SLAYT 13: DESTEKLENEN CİHAZ EKOSİSTEMİ VE PROTOKOL ENTEGRASYONLARI

### **Çok-Vendörlü Altyapı Desteği**

NABS-GP, Scrapli Sürücüleri, Custom Driver'lar ve Paramiko aracılığıyla geniş bir cihaz yelpazesini destekler:

* **Cisco Systems:** Cisco IOS, IOS-XE, NX-OS
* **Fortinet:** FortiGate / FortiSwitch (Scrapli GenericDriver ile ham CLI sayfalama kontrolü)
* **Palo Alto Networks:** PAN-OS
* **Juniper Networks:** Junos OS
* **Huawei:** VRP (`display current-configuration`)
* **Aruba / HP:** Aruba OS-CX, ProCurve
* **MikroTik:** RouterOS (`/export`)
* **OpenWrt / Linux:** `uci export` ve `/etc/config/` taraması (Paramiko SSH entegrasyonu)

> **Eski Cihaz (Legacy KEX/Cipher) Desteği:** Eski nesil OpenSSH algoritmalarını zorunlu kılan cihazlar için konteyner seviyesinde özel `ssh_config` şablonu gömülmüştür.

---

## SLAYT 14: GÖZLEMLENEBİLİRLİK (OBSERVABILITY) VE KURUMSAL ENTEGRASYONLAR

### **1. Metrikler ve Gözlemlenebilirlik (Bölüm 11)**
* **Prometheus Uç Noktası:** `/metrics` adresi üzerinden aktif cihaz sayısı, başarılı/başarısız yedekleme sayıları, Celery kuyruk derinlikleri ve API yanıt süreleri sunulur.
* **Grafana Panoları:** Hazır Grafana dashboard yapılandırmaları (`docker-compose.observability.yml`):
  * **API & System Metrics:** HTTP istek sayıları, 5xx hatalar, latency.
  * **Backup Operations:** Yedekleme başarı oranları, vendor dağılımı.
  * **Security Dashboard:** Açık advisory durumları, risk skor trendleri.

### **2. Dış Sistem Entegrasyonları**
* **Webhook & Alarmlar:** Slack, Microsoft Teams ve Syslog (RFC 5424) entegrasyonu ile Kritik/Yüksek seviyeli güvenlik ihlallerinde anlık bildirim.
* **API Key Yönetimi:** Harici otomasyon sistemleri için SHA-256 özetli, rol kısıtlamalı API Key üretimi (`X-API-Key` başlığı).

---

## SLAYT 15: SİSTEM YÖNETİMİ, TLS VE SERTİFİKA OPERASYONLARI

### **Admin Ayarlar Paneli ve Canlı Yönetim**

* **Canlı Yapılandırma Override (Restart Gerektirmez):**
  * Webhook adresleri, veri saklama süresi (`DATA_RETENTION_DAYS`), login rate-limit limitleri, Ollama adresi ve LDAP ayarları GUI'den yönetilir.
  * Çözümleme Önceliği: **DB Override ➔ Ortam Değişkeni (.env) ➔ Varsayılan Değer**.
* **GUI Üzerinden TLS Sertifika Yönetimi:**
  * Admin kullanıcıları web arayüzünden Caddy reverse-proxy için PEM formatında Sertifika ve Private Key yükleyebilir.
  * Backend, sertifika-anahtar tutarlılığını ve kalan geçerlilik süresini doğrular. Sertifika private key'i `0600` izinleriyle güvenli volume'a yazılır ve Caddy kesintisiz olarak yeni sertifikayı yükler (Zero-Downtime TLS Renewal).
  * **TLS Durum Testi:** GUI üzerinden canlı HTTPS sertifikası okunarak kalan gün sayısı ve bitiş uyarıları görüntülenebilir.

---

## SLAYT 16: DAĞITIM (DEPLOYMENT), KURULUM SİHİRBAZI VE ÖLÇEKLENEBİLİRLİK

### **Hızlı Kurulım Sihirbazı (`install.sh`)**
Platform, karmaşık ortam değişkenleri ve servis bağımlılıklarını tek komutla kuran interaktif bir kurulum sihirbazına sahiptir:
```bash
./install.sh
```
* Sihirbaz alan adını, secret'ları, Vault/TLS/Observability tercihlerini sorar, `.env` dosyasını üretir, Docker konteynerlerini ayağa kaldırır, veritabanını ilklendirir ve sağlık kontrollerini yapar.

### **Sistem Kaynak Gereksinimleri & Ölçekleme (Sizing)**

| Ölçek Seviyesi | Cihaz Sayısı | Önerilen Donanım | Worker Yapılandırması |
|---|---|---|---|
| **Küçük / PoC** | 1 - 500 Cihaz | 4 vCPU / 8 GB RAM | 1 Celery Worker |
| **Orta (Kurumsal)** | 500 - 2.000 Cihaz | 8 vCPU / 16 GB RAM | 2-4 Celery Worker |
| **Büyük Ölçek** | 5.000+ Cihaz | 8+ vCPU / 16+ GB RAM | Yatay Çoğaltılmış Worker'lar + Redis Cluster + PG Tuning |

---

## SLAYT 17: PROJE FAZ TAMAMLANMA DURUMU VE YOL HARİTASI

### **Faz Tamamlanma Tablosu**

| Faz | Açıklama | Durum |
|---|---|---|
| **Faz 1** | Veritabanı şeması, AES-256 Vault, FastAPI, JWT, Celery/Redis, Scrapli, Git entegrasyonu, SFTPGo webhook. | %100 Tamamlandı |
| **Faz 2** | SNMP/ping/SSH keşfi, OS tanıma, diff motoru, React NMS dashboard, RBAC, append-only audit. | %100 Tamamlandı |
| **Faz 3** | YAML politika motoru, NVD CVE/CPE eşleme, dinamik risk skorlama, PDF raporlama. | %100 Tamamlandı |
| **Faz 4** | Ollama LLM analizi, pgvector RAG, Chat-with-Network, remediation üretim & onay state machine. | %100 Tamamlandı |
| **Faz 5** | Slack/Teams/Syslog bildirimleri, LDAP SSO + TOTP MFA, dağıtık Celery kuyrukları, Locust yük testi. | %100 Tamamlandı |
| **Faz 6 (Ek)** | GUI - API tam entegrasyonu: varlık yönetimi, credential kasası, bulgu susturma, L2 keşif, canlı topoloji haritası. | %100 Tamamlandı |
| **Ek Üretim Modülleri**| Caddy TLS yönetimi, Vault secret backend, Prometheus/Grafana observability overlay'leri. | %100 Tamamlandı |

---

## SLAYT 18: ÖZET VE SONUÇ

### **NABS-GP Neden Tercih Edilmeli?**

1. **Tam Kapsamlı Yönetişim:** Konfigürasyon yedeklemeden güvenlik denetimine, canlı topolojiden AI destekli iyileştirmeye kadar uçtan uca çözüm.
2. **Güvenlik ve Mahremiyet Garantisi:** Fail-closed mimari, AES-256-GCM şifreleme, onaysız cihaz müdahalesi olmaması ve tamamen kurum içinde (On-Prem) çalışan yerel AI.
3. **Yüksek Uyumluluk & Esneklik:** Cisco'dan MikroTik'e, Fortinet'ten OpenWrt Linux kutularına kadar geniş cihaz ve protokol desteği.
4. **Üretim Erişilebilirliği:** Docker Compose ve `install.sh` sihirbazı ile dakikalar içinde canlıya alınabilen, yatay ölçeklenebilir altyapı.

---
*Doküman Sonu — NABS-GP Teknik Sunum Paketi v1.1.0*
