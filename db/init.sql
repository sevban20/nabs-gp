-- NABS-GP PostgreSQL 16+ DDL (Spec v1.1 Section 3 + Section 8)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Network Zones for multi-site and tenancy hierarchy
CREATE TABLE network_zones (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    parent_id INT REFERENCES network_zones(id) ON DELETE CASCADE,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_zones_parent ON network_zones(parent_id);

-- Secure Credential Vault (secrets AES-256-GCM encrypted in backend)
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(150) NOT NULL,
    username VARCHAR(100) NOT NULL,
    password_encrypted TEXT NOT NULL,
    secret_encrypted TEXT,           -- Cisco enable / privilege secret
    ssh_key_private TEXT,            -- Optional private-key auth
    passphrase_encrypted TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Device Asset Inventory
CREATE TABLE assets (
    id SERIAL PRIMARY KEY,
    uuid UUID UNIQUE DEFAULT uuid_generate_v4(),
    hostname VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL UNIQUE,
    vendor VARCHAR(64) NOT NULL,     -- 'cisco_ios','fortinet','paloalto','juniper_junos'
    model VARCHAR(128),
    os_version VARCHAR(64),
    serial_number VARCHAR(128),
    zone_id INT REFERENCES network_zones(id) ON DELETE SET NULL,
    credential_id UUID REFERENCES credentials(id) ON DELETE SET NULL,
    backup_method VARCHAR(32) NOT NULL, -- 'ACTIVE_SSH','ACTIVE_API','PASSIVE_SFTP','PASSIVE_TFTP'
    cron_schedule VARCHAR(64) DEFAULT '0 2 * * *',
    risk_score INT DEFAULT 100 CHECK (risk_score >= 0 AND risk_score <= 100),
    is_active BOOLEAN DEFAULT TRUE,
    is_reachable BOOLEAN,                       -- up/down (periyodik TCP probe)
    last_reachability_check_at TIMESTAMP WITH TIME ZONE,
    last_successful_backup_at TIMESTAMP WITH TIME ZONE,
    has_drift BOOLEAN DEFAULT FALSE,            -- golden config'ten sapma
    last_drift_check_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_assets_vendor ON assets(vendor);
CREATE INDEX idx_assets_ip ON assets(ip_address);

-- History of Backup Jobs
CREATE TABLE backup_history (
    id BIGSERIAL PRIMARY KEY,
    asset_id INT REFERENCES assets(id) ON DELETE CASCADE,
    triggered_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(32) NOT NULL,     -- 'SUCCESS','FAILED','TIMEOUT','IN_PROGRESS'
    method_used VARCHAR(32) NOT NULL,
    commit_hash VARCHAR(64),
    config_size_bytes INT,
    lines_added INT DEFAULT 0,
    lines_deleted INT DEFAULT 0,
    error_log TEXT,
    triggered_by VARCHAR(128) NOT NULL -- 'CRON_ENGINE','USER_ID_[X]','SFTP_WEBHOOK'
);
CREATE INDEX idx_backup_asset_status ON backup_history(asset_id, status);

-- Security Advisories (rule scanning, CVEs, AI analysis results)
CREATE TABLE security_advisories (
    id BIGSERIAL PRIMARY KEY,
    asset_id INT REFERENCES assets(id) ON DELETE CASCADE,
    rule_id VARCHAR(64) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    remediation TEXT,
    severity VARCHAR(32) NOT NULL,   -- 'CRITICAL','HIGH','MEDIUM','LOW','INFO'
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE,
    is_silenced BOOLEAN DEFAULT FALSE,
    finding_source VARCHAR(64) NOT NULL -- 'STATIC_RULE_ENGINE','LLM_ANALYZER','CVE_MATCH'
);
CREATE INDEX idx_advisories_asset_severity ON security_advisories(asset_id, severity)
    WHERE resolved_at IS NULL;

-- Remediation approval workflow (Spec Section 8)
CREATE TABLE remediation_actions (
    id BIGSERIAL PRIMARY KEY,
    advisory_id BIGINT REFERENCES security_advisories(id) ON DELETE CASCADE,
    generated_commands TEXT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING_APPROVAL',
    -- 'DRAFT','PENDING_APPROVAL','APPROVED','REJECTED','STAGED','APPLIED','ROLLED_BACK'
    requested_by VARCHAR(128),
    approved_by VARCHAR(128),
    approved_at TIMESTAMP WITH TIME ZONE,
    maintenance_window VARCHAR(255),   -- ISO aralık metni; ORM (String) ile uyumlu, cross-DB
    rollback_commands TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Users (Phase-1 JWT baseline, Spec Section 7; Faz 5: TOTP MFA)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'viewer', -- 'viewer','operator','approver','admin'
    is_active BOOLEAN DEFAULT TRUE,
    mfa_secret_encrypted TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Harici entegrasyon API anahtarlari (ham anahtar saklanmaz, yalnizca SHA-256 ozeti)
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    prefix VARCHAR(12) NOT NULL,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    role VARCHAR(32) NOT NULL DEFAULT 'viewer',
    is_active BOOLEAN DEFAULT TRUE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_by VARCHAR(128),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Uygulama-ici operasyonel ayarlar (admin panelinden). Bootstrap secret'lar burada DEGIL.
CREATE TABLE app_settings (
    key VARCHAR(64) PRIMARY KEY,
    value TEXT,
    updated_by VARCHAR(128),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Faz 2 Sprint 15-16: immutable audit izi (append-only; uygulama katmaninda
-- UPDATE/DELETE yolu yoktur)
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(128) NOT NULL,
    method VARCHAR(10) NOT NULL,
    path VARCHAR(512) NOT NULL,
    status_code INT NOT NULL,
    source_ip VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_audit_user_time ON audit_log(username, created_at);

-- Config baseline (golden referans): drift tespitinin karsilastirma noktasi
CREATE TABLE config_baselines (
    id SERIAL PRIMARY KEY,
    asset_id INT REFERENCES assets(id) ON DELETE CASCADE UNIQUE,
    commit_hash VARCHAR(64) NOT NULL,
    content_hash VARCHAR(64) NOT NULL,
    note TEXT,
    set_by VARCHAR(128),
    set_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- L2 kesif: ARP + MAC tablosu + komsulukla bulunan uc cihazlar
CREATE TABLE discovered_hosts (
    id BIGSERIAL PRIMARY KEY,
    mac VARCHAR(12) NOT NULL,
    ip_address VARCHAR(64),
    oui_vendor VARCHAR(64),
    seen_on_device VARCHAR(255) NOT NULL,
    seen_on_interface VARCHAR(128),
    vlan VARCHAR(16),
    source VARCHAR(16) NOT NULL,
    is_onboarded BOOLEAN DEFAULT FALSE,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (mac, seen_on_device)
);
CREATE INDEX idx_disc_mac ON discovered_hosts(mac);

-- Ag topolojisi: LLDP/CDP komsuluk kenarlari (ag haritasi kaynagi)
CREATE TABLE topology_links (
    id BIGSERIAL PRIMARY KEY,
    source_device VARCHAR(255) NOT NULL,
    remote_device VARCHAR(255) NOT NULL,
    remote_ip VARCHAR(64),
    local_interface VARCHAR(128),
    remote_interface VARCHAR(128),
    platform VARCHAR(255),
    protocol VARCHAR(16) NOT NULL,
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_topology_source ON topology_links(source_device);

-- Faz 4 Sprint 29-30: RAG chunk deposu.
-- Uretimde pgvector onerilir:
--   CREATE EXTENSION IF NOT EXISTS vector;
--   ALTER TABLE rag_chunks ADD COLUMN embedding vector(768);
-- embedding_json tasinabilirlik icin korunur (SQLite fallback).
CREATE TABLE rag_chunks (
    id BIGSERIAL PRIMARY KEY,
    source VARCHAR(255) NOT NULL,
    chunk_text TEXT NOT NULL,
    embedding_json TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
