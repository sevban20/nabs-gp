"""Auto-Remediation & Human-in-the-Loop Approval Workflow (Spec Section 8).

State machine:
  DRAFT -> PENDING_APPROVAL -> APPROVED / REJECTED -> STAGED -> APPLIED -> ROLLED_BACK

Enforced rules:
- No transition APPROVED -> APPLIED may skip STAGED for CRITICAL/HIGH findings.
- Approver != requester (enforced at API layer, not just convention).
- No unsupervised write-back (Spec 13.5): 'APPLIED' here records that an
  operator applied the change through the (future, Phase-4) push component;
  this API never sends commands to a device.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.auth import require_role
from app.core.database import get_db
from app.models.models import RemediationAction, SecurityAdvisory
from app.schemas.schemas import RemediationCreate, RemediationOut

router = APIRouter()

VALID_TRANSITIONS: dict[str, set[str]] = {
    "DRAFT": {"PENDING_APPROVAL"},
    "PENDING_APPROVAL": {"APPROVED", "REJECTED"},
    "APPROVED": {"STAGED", "APPLIED"},  # APPLIED direct only for MEDIUM/LOW/INFO
    "REJECTED": set(),
    "STAGED": {"APPLIED", "ROLLED_BACK"},
    "APPLIED": {"ROLLED_BACK"},
    "ROLLED_BACK": set(),
}


@router.get("/remediations", response_model=list[RemediationOut])
def list_remediations(status: str | None = None, db: Session = Depends(get_db),
                      _user: dict = Depends(require_role("viewer"))):
    q = db.query(RemediationAction)
    if status:
        q = q.filter(RemediationAction.status == status)
    return q.order_by(RemediationAction.created_at.desc()).limit(200).all()


@router.post("/remediations", response_model=RemediationOut, status_code=201)
def create_remediation(payload: RemediationCreate, db: Session = Depends(get_db),
                       user: dict = Depends(require_role("operator"))):
    advisory = db.get(SecurityAdvisory, payload.advisory_id)
    if not advisory:
        raise HTTPException(status_code=404, detail="Advisory not found.")
    action = RemediationAction(
        advisory_id=payload.advisory_id,
        generated_commands=payload.generated_commands,
        rollback_commands=payload.rollback_commands,
        status="PENDING_APPROVAL",
        requested_by=user["sub"],
    )
    db.add(action)
    db.commit()
    db.refresh(action)
    return action


@router.post("/remediations/{action_id}/transition", response_model=RemediationOut)
def transition_remediation(action_id: int, new_status: str,
                           db: Session = Depends(get_db),
                           user: dict = Depends(require_role("approver"))):
    action = db.get(RemediationAction, action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Remediation action not found.")

    allowed = VALID_TRANSITIONS.get(action.status, set())
    if new_status not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Illegal transition {action.status} -> {new_status}. Allowed: {sorted(allowed)}",
        )

    if new_status in ("APPROVED", "REJECTED"):
        # Approver may not approve their own request (Spec Section 8).
        if action.requested_by and action.requested_by == user["sub"]:
            raise HTTPException(
                status_code=403,
                detail="Approver must differ from the requester (four-eyes principle).",
            )
        action.approved_by = user["sub"]
        action.approved_at = datetime.now(timezone.utc)

    if new_status == "APPLIED" and action.status == "APPROVED":
        # CRITICAL/HIGH findings must pass through STAGED first.
        advisory = db.get(SecurityAdvisory, action.advisory_id) if action.advisory_id else None
        if advisory and advisory.severity in ("CRITICAL", "HIGH"):
            raise HTTPException(
                status_code=400,
                detail="CRITICAL/HIGH remediations must be STAGED (lab-validated) before APPLIED.",
            )

    action.status = new_status
    db.commit()
    db.refresh(action)
    return action
