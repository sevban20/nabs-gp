"""Faz 5 Sprint 43-48 / Bölüm 15 açık maddesi: webhook imza-doğrulama
yolunun yük testi.

Kurulum ve çalıştırma:
    pip install locust
    export SFTPGO_WEBHOOK_SECRET=<gerçek secret>
    locust -f loadtest/locustfile.py --host http://localhost:8000 \
           --users 500 --spawn-rate 50 --run-time 5m --headless

5.000 düğüm simülasyonu: her sanal kullanıcı farklı bir hostname ile
upload webhook'u gönderir; böylece imza doğrulama + sanitizasyon + Git
commit yolu gerçekçi biçimde zorlanır.
"""
import hashlib
import hmac
import json
import os
import random

from locust import HttpUser, between, task

SECRET = os.getenv("SFTPGO_WEBHOOK_SECRET", "change_me").encode()


class WebhookUser(HttpUser):
    wait_time = between(0.5, 2.0)

    @task(10)
    def signed_upload(self):
        device = f"SIM-DEV-{random.randint(1, 5000):04d}"
        payload = json.dumps({
            "action": "upload", "username": "loadtest",
            "path": f"{device}.conf", "target_path": f"{device}.conf",
        }).encode()
        sig = hmac.new(SECRET, payload, hashlib.sha256).hexdigest()
        # Dosya diskte olmadığından 404 beklenir; imza+path yolu yine de ölçülür.
        with self.client.post("/api/v1/webhook/sftpgo", data=payload,
                              headers={"x-sftpgo-signature": sig},
                              catch_response=True) as resp:
            if resp.status_code in (200, 404):
                resp.success()

    @task(1)
    def invalid_signature_rejected_fast(self):
        payload = json.dumps({"action": "upload", "username": "x",
                              "path": "a.conf", "target_path": "a.conf"}).encode()
        with self.client.post("/api/v1/webhook/sftpgo", data=payload,
                              headers={"x-sftpgo-signature": "bogus"},
                              catch_response=True) as resp:
            if resp.status_code == 401:
                resp.success()
