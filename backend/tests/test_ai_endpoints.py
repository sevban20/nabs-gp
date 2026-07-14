"""AI uçları LLM erişilemezken 500 yerine 503 dönmeli (regresyon:
httpx.ConnectError -> Unhandled 500)."""
import pytest
from fastapi.testclient import TestClient

from app.ai.analyzer import LLMUnavailableError
from app.core.auth import hash_password
from app.core.database import Base, SessionLocal, engine
from app.main import app
from app.models.models import SecurityAdvisory, User

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    for u, r in [("ai_op", "operator")]:
        if not db.query(User).filter(User.username == u).first():
            db.add(User(username=u, password_hash=hash_password("Passw0rd!x"), role=r))
    db.commit()
    db.close()
    yield


def _token(u):
    r = client.post("/api/v1/auth/token", data={"username": u, "password": "Passw0rd!x"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_chat_returns_503_when_llm_unavailable(monkeypatch):
    import app.api.v1.endpoints.ai as ai_mod

    async def boom(*a, **k):
        raise LLMUnavailableError("bağlanılamadı")

    monkeypatch.setattr(ai_mod.analyzer, "chat", boom)
    r = client.post("/api/v1/ai/chat", headers=_token("ai_op"),
                    json={"question": "en riskli cihaz?"})
    assert r.status_code == 503
    assert "Ollama" in r.json()["detail"]


def test_generate_remediation_returns_503_when_llm_unavailable(monkeypatch):
    import app.api.v1.endpoints.ai as ai_mod

    db = SessionLocal()
    adv = SecurityAdvisory(rule_id="AI-T", title="t", description="d",
                           severity="HIGH", finding_source="STATIC_RULE_ENGINE")
    db.add(adv)
    db.commit()
    adv_id = adv.id
    db.close()

    async def boom(*a, **k):
        raise LLMUnavailableError("bağlanılamadı")

    monkeypatch.setattr(ai_mod.analyzer, "generate_remediation", boom)
    r = client.post(f"/api/v1/ai/advisories/{adv_id}/generate-remediation",
                    headers=_token("ai_op"))
    assert r.status_code == 503


def _patch_httpx_connect_error(monkeypatch):
    """httpx.AsyncClient.post'u ConnectError fırlatacak şekilde değiştirir
    (gerçek ağ/proxy'ye bağımlı olmadan bağlantı hatasını simüle eder)."""
    import httpx

    async def boom(self, *a, **k):
        raise httpx.ConnectError("All connection attempts failed")

    monkeypatch.setattr(httpx.AsyncClient, "post", boom)


def test_generate_raises_llm_unavailable_on_connect_error(monkeypatch):
    """_generate bağlantı hatasında LLMUnavailableError fırlatmalı."""
    import asyncio

    from app.ai.analyzer import AIConfigAnalyzer
    _patch_httpx_connect_error(monkeypatch)
    an = AIConfigAnalyzer()
    with pytest.raises(LLMUnavailableError):
        asyncio.run(an._generate("sys", "user"))


def test_analyze_config_returns_empty_on_connect_error(monkeypatch):
    """analyze_config (arka plan) LLM yoksa boş liste döner, hata fırlatmaz."""
    import asyncio

    from app.ai.analyzer import AIConfigAnalyzer
    _patch_httpx_connect_error(monkeypatch)
    an = AIConfigAnalyzer()
    out = asyncio.run(an.analyze_config("HOST", "cisco_ios", "hostname HOST"))
    assert out == []


def test_ai_status_unreachable(monkeypatch):
    """/ai/status Ollama erişilemezken reachable=false döner (200, çökmez)."""
    import httpx

    async def boom(self, *a, **k):
        raise httpx.ConnectError("no")
    monkeypatch.setattr(httpx.AsyncClient, "get", boom)
    r = client.get("/api/v1/ai/status", headers=_token("ai_op"))
    assert r.status_code == 200
    body = r.json()
    assert body["reachable"] is False and body["model_ready"] is False


def test_ai_status_reachable_with_model(monkeypatch):
    """Ollama erişilir ve model yüklüyse model_ready=true."""
    import httpx

    class FakeResp:
        status_code = 200
        def json(self):
            return {"models": [{"name": "llama3:8b-instruct"}, {"name": "nomic-embed-text"}]}

    async def ok(self, *a, **k):
        return FakeResp()
    monkeypatch.setattr(httpx.AsyncClient, "get", ok)
    r = client.get("/api/v1/ai/status", headers=_token("ai_op"))
    assert r.status_code == 200
    body = r.json()
    assert body["reachable"] is True and body["model_ready"] is True
    assert "llama3:8b-instruct" in body["models"]


def test_base_url_derivation():
    from app.ai.analyzer import AIConfigAnalyzer
    an = AIConfigAnalyzer(endpoint_url="http://host.docker.internal:11434/api/generate")
    assert an._base_url() == "http://host.docker.internal:11434"
