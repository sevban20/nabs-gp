FROM python:3.11-slim

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

# Non-root çalıştırma: uygulama ve veri dizinleri appuser'a ait
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /var/nabs/git_repo /var/nabs/sftpgo_uploads \
    && chown -R appuser:appuser /srv/nabs /var/nabs
USER appuser

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
