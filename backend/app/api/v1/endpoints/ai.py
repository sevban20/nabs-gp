"""Faz 4 uçları: Chat-with-Network, RAG indeksleme, değişiklik özeti,
LLM remediation üretimi (yalnızca onay kuyruğuna yazar)."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.ai.analyzer import AIConfigAnalyzer, LLMUnavailableError
from app.core.auth import require_role
from app.core.database import get_db
from app.models.models import Asset, RemediationAction, SecurityAdvisory

router = APIRouter()
analyzer = AIConfigAnalyzer()

LLM_UNAVAILABLE_HINT = (
    "Yerel LLM (Ollama) erişilemez. Ollama servisinin çalıştığını ve "
    "OLLAMA_ENDPOINT/OLLAMA_MODEL ayarlarının doğru olduğunu kontrol edin. "
    "Bu özellik yerel bir LLM sunucusu gerektirir."
)


class ChatRequest(BaseModel):
    question: str


class IndexRequest(BaseModel):
    source: str
    text: str


@router.get("/ai/status")
async def ai_status(_user: dict = Depends(require_role("viewer"))):
    """Yerel LLM (Ollama) erişilebilir mi ve model yüklü mü? Chat arayüzü
    kullanıcıyı önceden uyarmak için kullanır."""
    return await analyzer.check_status()


@router.post("/ai/chat")
async def chat_with_network(payload: ChatRequest, db: Session = Depends(get_db),
                            _user: dict = Depends(require_role("viewer"))):
    from app.ai.rag import retrieve

    # Bağlam 1: envanter özeti
    assets = db.query(Asset).all()
    inventory = "\n".join(
        f"- {a.hostname} ({a.ip_address}, {a.vendor}, risk={a.risk_score})" for a in assets
    )
    # Bağlam 2: açık kritik/yüksek bulgular
    advisories = (db.query(SecurityAdvisory)
                  .filter(SecurityAdvisory.resolved_at.is_(None),
                          SecurityAdvisory.severity.in_(["CRITICAL", "HIGH"]))
                  .limit(30).all())
    findings = "\n".join(f"- [{a.severity}] {a.title} (asset_id={a.asset_id})" for a in advisories)
    # Bağlam 3: RAG (benchmark chunk'ları) — Ollama yoksa sessizce atla
    rag_blocks = []
    try:
        rag_blocks = [c["text"] for c in await retrieve(payload.question)]
    except Exception:
        pass

    context = [f"ENVANTER:\n{inventory or '(boş)'}",
               f"AÇIK BULGULAR:\n{findings or '(yok)'}", *rag_blocks]
    try:
        answer = await analyzer.chat(payload.question, context)
    except LLMUnavailableError:
        raise HTTPException(status_code=503, detail=LLM_UNAVAILABLE_HINT)
    return {"answer": answer, "rag_chunks_used": len(rag_blocks)}


@router.post("/ai/index-benchmark", status_code=201)
async def index_benchmark(payload: IndexRequest,
                          _user: dict = Depends(require_role("operator"))):
    from app.ai.rag import index_document
    try:
        count = await index_document(payload.source, payload.text)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Embedding servisi erişilemez: {exc}")
    return {"source": payload.source, "chunks_indexed": count}


@router.post("/ai/advisories/{advisory_id}/generate-remediation", status_code=201)
async def generate_remediation(advisory_id: int, db: Session = Depends(get_db),
                               user: dict = Depends(require_role("operator"))):
    """LLM komut üretir ve PENDING_APPROVAL olarak kaydeder.
    Spec İlke 13.5: buradan cihaza giden hiçbir yol yoktur."""
    adv = db.get(SecurityAdvisory, advisory_id)
    if not adv:
        raise HTTPException(status_code=404, detail="Advisory not found.")
    asset = db.get(Asset, adv.asset_id) if adv.asset_id else None
    vendor = asset.vendor if asset else "cisco_ios"
    try:
        result = await analyzer.generate_remediation(vendor, {
            "title": adv.title, "description": adv.description, "remediation": adv.remediation})
    except LLMUnavailableError:
        raise HTTPException(status_code=503, detail=LLM_UNAVAILABLE_HINT)
    if not result["commands"]:
        raise HTTPException(status_code=502, detail="LLM komut üretemedi.")
    action = RemediationAction(
        advisory_id=adv.id, generated_commands=result["commands"],
        rollback_commands=result["rollback_commands"] or None,
        status="PENDING_APPROVAL", requested_by=user["sub"],
    )
    db.add(action)
    db.commit()
    db.refresh(action)
    return {"remediation_action_id": action.id, "status": action.status}


@router.get("/ai/assets/{asset_id}/summarize-change")
async def summarize_change(asset_id: int, commit_a: str, commit_b: str,
                           db: Session = Depends(get_db),
                           _user: dict = Depends(require_role("viewer"))):
    from app.services.git_engine import get_git_engine
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")
    diff = get_git_engine().get_diff(asset.hostname, commit_a, commit_b)
    if not diff:
        return {"summary": "İki commit arasında fark yok."}
    try:
        return {"summary": await analyzer.summarize_change(asset.hostname, diff)}
    except LLMUnavailableError:
        raise HTTPException(status_code=503, detail=LLM_UNAVAILABLE_HINT)
