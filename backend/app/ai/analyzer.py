"""Local LLM Prompt Orchestrator - Ollama Gateway (Spec Section 4.4).

Low temperature is intentional: raising it would increase finding
variety at the cost of determinism, which matters for reproducible
audits.
"""
import json
from typing import Dict, List

import httpx

from app.core.config import settings


class LLMUnavailableError(Exception):
    """Yerel LLM (Ollama) erişilemez olduğunda fırlatılır; etkileşimli
    uçlar bunu 503'e çevirir (500 yerine anlaşılır hata)."""


class AIConfigAnalyzer:
    def __init__(self, endpoint_url: str | None = None):
        # Sabit endpoint verilmezse admin ayarından (DB→env→default) canlı okunur
        self._fixed_endpoint = endpoint_url

    @property
    def endpoint(self) -> str:
        if self._fixed_endpoint:
            return self._fixed_endpoint
        from app.core.settings_service import get_setting
        return get_setting("OLLAMA_ENDPOINT", settings.OLLAMA_ENDPOINT)

    @property
    def model_name(self) -> str:
        from app.core.settings_service import get_setting
        return get_setting("OLLAMA_MODEL", settings.OLLAMA_MODEL)

    def _base_url(self) -> str:
        """generate/embeddings uç noktasından Ollama kök URL'sini çıkarır."""
        if "/api/" in self.endpoint:
            return self.endpoint.rsplit("/api/", 1)[0]
        return self.endpoint.rstrip("/")

    async def check_status(self) -> dict:
        """Ollama'ya erişilebilir mi ve yapılandırılan model yüklü mü?
        Chat arayüzü kullanıcıyı önceden bilgilendirmek için çağırır."""
        result = {"reachable": False, "model_ready": False, "models": [],
                  "endpoint": self.endpoint, "model": self.model_name}
        try:
            async with httpx.AsyncClient(timeout=5.0, trust_env=False) as client:
                resp = await client.get(f"{self._base_url()}/api/tags")
            if resp.status_code != 200:
                return result
            models = [m.get("name", "") for m in resp.json().get("models", [])]
        except httpx.RequestError:
            return result
        result["reachable"] = True
        result["models"] = models
        want = self.model_name.split(":")[0]
        result["model_ready"] = any(want in m for m in models)
        return result

    async def analyze_config(self, hostname: str, vendor: str, sanitized_config: str) -> List[Dict]:
        system_prompt = (
            "You are an expert network security auditor. Identify architectural "
            "security flaws, logical contradictions in firewall rules, or "
            "unhardened parameters. Respond ONLY with a valid JSON list of objects, "
            "no prose, no markdown fences, in this exact shape: "
            '[{"rule_id":"AI-01","title":"...","description":"...",'
            '"severity":"HIGH","remediation":"..."}]'
        )
        user_content = (
            f"Device Hostname: {hostname}\nVendor Type: {vendor}\n"
            f"Configuration:\n{sanitized_config}"
        )
        prompt = (
            f"<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n{system_prompt}<|eot_id|>"
            f"<|start_header_id|>user<|end_header_id|>\n{user_content}<|eot_id|>"
            f"<|start_header_id|>assistant<|end_header_id|>"
        )
        payload = {
            "model": self.model_name, "prompt": prompt, "stream": False,
            "options": {"temperature": 0.1},
        }
        # analyze_config arka plan/tarama bağlamında çağrılır; LLM yoksa
        # sert hata yerine boş bulgu döner (opsiyonel AI zenginleştirme).
        # trust_env=False: yerel LLM kurumsal proxy'den geçmemeli
        try:
            async with httpx.AsyncClient(timeout=120.0, trust_env=False) as client:
                response = await client.post(self.endpoint, json=payload)
                if response.status_code != 200:
                    return []
                raw_text = response.json().get("response", "[]")
        except httpx.RequestError:
            return []
        return self.parse_llm_output(raw_text)

    async def _generate(self, system_prompt: str, user_content: str,
                        temperature: float = 0.1) -> str:
        """Ortak Ollama üretim çağrısı (Llama 3 chat şablonu)."""
        prompt = (
            f"<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n{system_prompt}<|eot_id|>"
            f"<|start_header_id|>user<|end_header_id|>\n{user_content}<|eot_id|>"
            f"<|start_header_id|>assistant<|end_header_id|>"
        )
        payload = {"model": self.model_name, "prompt": prompt, "stream": False,
                   "options": {"temperature": temperature}}
        try:
            async with httpx.AsyncClient(timeout=120.0, trust_env=False) as client:
                response = await client.post(self.endpoint, json=payload)
        except httpx.RequestError as exc:
            # Bağlantı/timeout: etkileşimli uçlar 503'e çevirsin diye fırlat
            raise LLMUnavailableError(
                f"Yerel LLM'e ({self.endpoint}) bağlanılamadı: {exc}") from exc
        if response.status_code != 200:
            raise LLMUnavailableError(
                f"Yerel LLM {response.status_code} döndü (model '{self.model_name}' "
                "yüklü olmayabilir).")
        return response.json().get("response", "")

    async def analyze_contradictions(self, hostname: str,
                                     sanitized_config: str) -> List[Dict]:
        """Faz 4 Sprint 27-28: çok kurallı mantıksal çelişki analizi
        (örn. birbirini gölgeleyen/çelişen firewall kuralları)."""
        system_prompt = (
            "You are a firewall policy logician. Find rules that contradict, "
            "shadow, or make each other unreachable (e.g. a broad deny before "
            "a specific permit). Respond ONLY with a JSON list: "
            '[{"rule_id":"AI-LOGIC-01","title":"...","description":"...",'
            '"severity":"HIGH","remediation":"..."}]. Empty list if none.'
        )
        raw = await self._generate(system_prompt,
                                   f"Device: {hostname}\nConfiguration:\n{sanitized_config}")
        return self.parse_llm_output(raw)

    async def generate_remediation(self, vendor: str, finding: Dict) -> Dict:
        """Faz 4 Sprint 33-34: düzeltme komutu üretimi. Üretilen komutlar
        HİÇBİR ZAMAN doğrudan cihaza gitmez; PENDING_APPROVAL durumunda
        remediation_actions'a yazılır (Spec Bölüm 8 ile birlikte gelir)."""
        system_prompt = (
            f"You generate {vendor} CLI remediation for a security finding. "
            "Respond ONLY with JSON: "
            '{"commands":"...", "rollback_commands":"..."}. '
            "Commands must be minimal, idempotent and reversible."
        )
        raw = await self._generate(
            system_prompt,
            f"Finding: {finding.get('title')}\nDetails: {finding.get('description')}\n"
            f"Suggested direction: {finding.get('remediation')}")
        try:
            start, end = raw.find("{"), raw.rfind("}") + 1
            data = json.loads(raw[start:end])
            return {"commands": data.get("commands", ""),
                    "rollback_commands": data.get("rollback_commands", "")}
        except Exception:
            return {"commands": "", "rollback_commands": ""}

    async def summarize_change(self, hostname: str, diff_text: str) -> str:
        """Faz 4 Sprint 35-36: doğal dil değişiklik özeti."""
        system_prompt = (
            "You summarize network configuration diffs for a change-review "
            "audience in 2-4 sentences. Mention security-relevant changes first. "
            "Respond in Turkish."
        )
        raw = await self._generate(system_prompt,
                                   f"Device: {hostname}\nUnified diff:\n{diff_text}",
                                   temperature=0.2)
        return raw.strip() or "Özet üretilemedi (LLM erişilemez olabilir)."

    async def chat(self, question: str, context_blocks: List[str]) -> str:
        """Faz 4 Sprint 31-32: Chat-with-Network — envanter + RAG bağlamıyla
        soru-cevap."""
        system_prompt = (
            "You are NABS-GP's network assistant. Answer ONLY from the provided "
            "context (inventory, findings, benchmark excerpts). If the context "
            "is insufficient, say so. Respond in the user's language."
        )
        context = "\n\n---\n\n".join(context_blocks) or "(bağlam yok)"
        raw = await self._generate(system_prompt,
                                   f"Context:\n{context}\n\nQuestion: {question}",
                                   temperature=0.3)
        return raw.strip() or "Yanıt üretilemedi (LLM erişilemez olabilir)."

    @staticmethod
    def parse_llm_output(raw_text: str) -> List[Dict]:
        try:
            start, end = raw_text.find("["), raw_text.rfind("]") + 1
            return json.loads(raw_text[start:end])
        except Exception:
            return [{
                "rule_id": "AI-PARSE-ERR", "title": "Parsing Error",
                "description": "LLM did not return parseable JSON.",
                "severity": "INFO", "remediation": "Review the configuration manually.",
            }]
