"""Pydantic v2 request/response schemas."""
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


# --- Auth ---
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=8)
    role: str = Field(default="viewer", pattern="^(viewer|operator|approver|admin)$")


# --- Credentials (vault) ---
class CredentialCreate(BaseModel):
    name: str
    username: str
    password: str
    secret: str | None = None
    ssh_key_private: str | None = None
    passphrase: str | None = None


class CredentialOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    username: str
    created_at: datetime
    # Encrypted fields are intentionally never exposed.


# --- Assets ---
class AssetCreate(BaseModel):
    hostname: str
    ip_address: str
    vendor: str = Field(pattern="^(cisco_ios|fortinet|fortiswitch|paloalto|juniper_junos|"
                                "huawei_vrp|aruba_aoscx|aruba_procurve|mikrotik|openwrt|linux)$")
    model: str | None = None
    os_version: str | None = None
    serial_number: str | None = None
    zone_id: int | None = None
    credential_id: str | None = None
    backup_method: str = Field(pattern="^(ACTIVE_SSH|ACTIVE_API|PASSIVE_SFTP|PASSIVE_TFTP)$")
    cron_schedule: str = "0 2 * * *"


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    uuid: str
    hostname: str
    ip_address: str
    vendor: str
    model: str | None
    os_version: str | None
    backup_method: str
    risk_score: int
    is_active: bool
    is_reachable: bool | None
    has_drift: bool
    last_successful_backup_at: datetime | None


# --- Advisories ---
class AdvisoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    asset_id: int | None
    rule_id: str
    title: str
    description: str
    remediation: str | None
    severity: str
    detected_at: datetime
    resolved_at: datetime | None
    is_silenced: bool
    finding_source: str


# --- Remediation workflow ---
class RemediationCreate(BaseModel):
    advisory_id: int
    generated_commands: str
    rollback_commands: str | None = None


class RemediationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    advisory_id: int | None
    generated_commands: str
    status: str
    requested_by: str | None
    approved_by: str | None
    approved_at: datetime | None
    rollback_commands: str | None
    created_at: datetime


# --- Backup history ---
class BackupHistoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    asset_id: int | None
    triggered_at: datetime
    completed_at: datetime | None
    status: str
    method_used: str
    commit_hash: str | None
    triggered_by: str
