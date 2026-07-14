# NABS-GP — Çözüm Genel Bakış (Satış Öncesi)

**Network Asset, Backup & Security Governance Platform**
Heterojen, çok-vendörlü ağ altyapıları için birleşik konfigürasyon yedekleme, keşif, güvenlik denetimi ve yönetişim platformu.

---

## 1. Problem

Kurumsal ağlar yüzlerce/binlerce farklı vendörden (Cisco, Fortinet, Palo Alto, Juniper, Huawei, Aruba, MikroTik…) cihaz barındırır. Konfigürasyon yedekleme, varlık takibi, güvenlik sıkılaştırma ve uyumluluk denetimi genelde **silolu, manuel ve denetlenemez** şekilde yürür. Sonuç: kaybolan config'ler, gözden kaçan güvenlik açıkları, denetim (audit) zorluğu ve arıza sonrası yavaş kurtarma.

## 2. Çözüm

NABS-GP bunları tek platformda otomatikleştirir:

- **Konfigürasyon yedekleme & sürümleme** — gömülü Git ile satır-satır diff, sürüm geçmişi, indirme/geri yükleme.
- **Katmanlı ağ keşfi & topoloji** — TCP/SNMP/SSH-banner tarama + LLDP/CDP komşuluk + ARP/MAC + OUI ile uç cihaz keşfi; canlı ağ haritası.
- **Güvenlik denetimi** — statik kural motoru + YAML politika + NVD CVE eşleme + yerel LLM (mahremiyet korumalı) analiz.
- **Risk skorlama & config drift** — her cihaza risk skoru; "golden" referanstan sapma tespiti + zamanlanmış uyumluluk taraması.
- **Yönetişimli düzeltme** — LLM önerilerinin insan onayı olmadan cihaza gitmediği onay iş akışı (dört-göz, staged).

## 3. Farklılaştırıcılar

| # | Değer | Nasıl |
|---|---|---|
| 1 | **Veri mahremiyeti** | AI analizi yerel LLM (Ollama) ile; config'ler kuruluş dışına çıkmaz. |
| 2 | **Güvenlik-önce (fail-closed)** | Secret'lar eksikse başlatmayı reddeder; onaysız cihaza-yazma yoktur. |
| 3 | **Çok-vendör + Linux** | 10+ vendör CLI + OpenWrt/Linux (uci export). MAC OUI ile üretici tanıma. |
| 4 | **Air-gapped desteği** | Hassas/izole bölgeler için pasif SFTP yedekleme (HMAC imzalı). |
| 5 | **Gerçek NMS deneyimi** | KPI panosu, canlı topoloji haritası, iş kuyruğu görünürlüğü, rol-duyarlı GUI. |
| 6 | **Entegrasyon-hazır** | REST API + API key; Slack/Teams/Syslog; Prometheus/Grafana; LDAP/AD; Vault. |
| 7 | **Denetlenebilirlik** | Append-only audit log, immutable config geçmişi, request-ID korelasyonu. |

## 4. Yetenek matrisi

| Alan | Yetenek |
|---|---|
| Yedekleme | Aktif SSH (Scrapli) · pasif SFTP (webhook) · zamanlanmış cron · Git diff/geçmiş/indirme · off-host mirror |
| Keşif | CIDR tarama (TCP/SNMP/SSH-banner) · LLDP/CDP komşuluk · ARP+MAC+OUI L2 envanteri · onboarding |
| Topoloji | Bağımlılıksız SVG ağ haritası · omurga + uç cihazlar · risk renklendirme · down tespiti |
| Güvenlik | Statik kurallar · YAML politika motoru · NVD CVE/CPE · yerel LLM analiz · çok-vendör secret maskeleme |
| Risk & uyumluluk | Ağırlıklı risk skoru · golden baseline · config drift + zamanlanmış sweep · PDF risk raporu |
| Yönetişim | Düzeltme onay state machine · dört-göz · MFA · RBAC · API key |
| Gözlemlenebilirlik | /metrics · Grafana panoları (API/Platform/Operasyon) · alarm kuralları |
| Yönetim | Admin ayar paneli · kullanıcı/rol yönetimi · TLS sertifika yükleme · LDAP/Vault durum testleri |

## 5. Desteklenen cihazlar

Cisco IOS/IOS-XE · Fortinet FortiGate/FortiSwitch · Palo Alto PAN-OS · Juniper Junos · Huawei VRP · Aruba OS-CX/ProCurve · MikroTik RouterOS · **OpenWrt/Linux (uci)**. SNMP/SSH-banner tanıma; MAC OUI ile üretici tahmini (~50 üretici).

## 6. Mimari (özet)

Ayrık, olay-güdümlü mikroservis: stateless FastAPI + yatay ölçeklenen Celery worker'lar + PostgreSQL/Redis/Git. Tümü Docker Compose; `install.sh` sihirbazıyla tek komut kurulum, opsiyonel TLS/observability/Vault overlay'leri. Detay: `docs/ARCHITECTURE.md`.

## 7. Güvenlik & uyumluluk duruşu

- AES-256-GCM kimlik bilgisi kasası, fail-closed anahtar yönetimi, opsiyonel Vault/KMS.
- RBAC + JWT + opsiyonel LDAP/AD + TOTP MFA.
- Append-only denetim izi; KVKK/GDPR için yapılandırılabilir veri saklama & silme.
- Onaysız cihaza-yazma yok; değişiklik onay iş akışı.
- Non-root konteynerler, TLS, login rate-limit, webhook imza doğrulama.

## 8. Dağıtım & boyutlandırma

| Ölçek | Kaynak | Not |
|---|---|---|
| 100-500 cihaz | 4 vCPU / 8 GB | Tek worker |
| ~2.000 cihaz | 8 vCPU / 16 GB | 2-4 worker |
| 5.000+ cihaz | 8+ vCPU / 16+ GB | Çok worker + Redis/PG tuning, dağıtık polling |

On-prem (havuz içi/air-gapped dahil). Bulut/hibrit destekli. Kurulum: `install.sh` (interaktif sihirbaz). İşletim: `docs/PRODUCTION_INSTALL.md`.

## 9. Yol haritası açık maddeleri (şeffaflık)

Alembic migration, 5.000-düğüm yük testi, OWASP pentest, veri-saklama hukuk onayı, cihaza yazma (write-back) bileşeni — bilinçli olarak faz sonrası/kapsam dışı. Test/PoC ortamı için platform hazırdır.

---

*Bu doküman satış öncesi teknik değerlendirme içindir. Teknik derinlik: `docs/ARCHITECTURE.md`; kurulum/işletim: `docs/PRODUCTION_INSTALL.md`.*
