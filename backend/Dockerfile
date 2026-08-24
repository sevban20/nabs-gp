# Taban imaj sabitlenmiştir: bookworm'da OpenSSH 9.2 gelir. Sabitlenmezse
# etiket eski bir bullseye'a (OpenSSH 8.4) düşebilir ve ssh seçenek adları değişir.
FROM python:3.11-slim-bookworm

# git: config sürümleme · openssh-client: Scrapli 'system' transport (ssh binary)
RUN apt-get update && apt-get install -y --no-install-recommends git openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/nabs
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY policies ./policies
# Eski ağ cihazları (Huawei/Fortinet vb.) için legacy KEX/cipher'lara izin veren ssh config
COPY deploy/ssh_config /srv/nabs/ssh_config

# Pubkey algoritma seçeneğinin adı OpenSSH sürümüne göre değişir (>=8.5 ile
# yeniden adlandırıldı). Derleme sırasında hangisinin kabul edildiğini ölçüp
# doğru olanı ekliyoruz; sonra config'i ssh'ın kendisine doğrulatıyoruz —
# hatalıysa build burada patlar, ilk yedekleme denemesinde değil.
RUN set -eux; \
    ssh -V; \
    if ssh -G -o 'PubkeyAcceptedAlgorithms=+ssh-rsa' probe >/dev/null 2>&1; then \
        echo '    PubkeyAcceptedAlgorithms +ssh-rsa' >> /srv/nabs/ssh_config; \
    else \
        echo '    PubkeyAcceptedKeyTypes +ssh-rsa' >> /srv/nabs/ssh_config; \
    fi; \
    ssh -G -F /srv/nabs/ssh_config buildprobe >/dev/null; \
    echo "ssh_config dogrulandi:"; grep -iE 'pubkey' /srv/nabs/ssh_config

# Non-root çalıştırma: uygulama ve veri dizinleri appuser'a ait
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /var/nabs/git_repo /var/nabs/sftpgo_uploads \
    && chown -R appuser:appuser /srv/nabs /var/nabs
USER appuser

EXPOSE 8000
# --proxy-headers: gerçek istemci IP'si X-Forwarded-For'dan okunur (login
# rate-limit ve audit source_ip doğru olsun diye). 8000 yalnızca 127.0.0.1'e
# ve docker ağına açık olduğundan forwarded-allow-ips=* güvenlidir.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
