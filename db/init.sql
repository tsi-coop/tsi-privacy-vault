-- init.sql
-- SQL script for initializing the PostgreSQL database schema for TSI Privacy Vault.

-- Create Table: api_user
CREATE TABLE api_user (
    api_key VARCHAR(255) PRIMARY KEY,
    api_secret VARCHAR(255) NOT NULL,
    client_name VARCHAR(255) NOT NULL UNIQUE,
    active BOOLEAN DEFAULT TRUE,
    created_datetime TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create Table: id_type_master
CREATE TABLE id_type_master (
    id_type_code VARCHAR(50) PRIMARY KEY,
    id_type_name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    validation_regex TEXT,
    active BOOLEAN DEFAULT TRUE
);

-- Insert initial ID types (Optional, but good for quick setup)
INSERT INTO id_type_master (id_type_code, id_type_name, validation_regex, active) VALUES
('AADHAAR', 'Aadhaar Number', '^\\d{4}\\s\\d{4}\\s\\d{4}$', TRUE),
('VOTER_ID', 'Voter ID', '^[A-Z]{3}\\d{7}$', TRUE),
('ABHA_ID', 'ABHA ID', '^\\d{2}-\\d{4}-\\d{4}-\\d{4}$', TRUE)
ON CONFLICT (id_type_code) DO NOTHING; -- Avoid errors if run multiple times

-- Create Table: event_log
CREATE TABLE event_log (
    log_id BIGSERIAL PRIMARY KEY,
    api_key VARCHAR(255) REFERENCES api_user(api_key),
    operation_type VARCHAR(50) NOT NULL,
    id_type_code VARCHAR(50) REFERENCES id_type_master(id_type_code),
    reference_key UUID REFERENCES id_vault(reference_key),
    log_datetime TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create Table: admin_user
CREATE TABLE admin_user (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE,
    role VARCHAR(50) NOT NULL DEFAULT 'AUDIT_VIEWER',
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP WITH TIME ZONE
);

-- 1. Master Table for ID and File Records
CREATE TABLE vault_registry (
    reference_key UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type VARCHAR(20) NOT NULL, -- 'ID' or 'FILE'
    id_type_code VARCHAR(50),        -- Aadhaar, Voter, etc. (for IDs)
    file_name TEXT,                  -- Original name (for Files)
    encrypted_content TEXT NOT NULL, -- The "Locked Box" (Encrypted Data)
    encrypted_data_key TEXT,         -- The "Locked Key" (Wrapped DEK)
    hashed_value_sha256 CHAR(64) NOT NULL, -- MANDATORY for BSA Part B
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. BSA 2023 Forensic Metadata (The "Evidence Log")
CREATE TABLE bsa_forensic_logs (
    log_id BIGSERIAL PRIMARY KEY,
    reference_key UUID REFERENCES vault_registry(reference_key),
    
    -- PART A: User/Machine Details
    device_make_model VARCHAR(255),
    device_serial_number VARCHAR(100),
    device_mac_address VARCHAR(50),
    device_imei_uid VARCHAR(100),    -- For mobile/tablet sources
    system_status VARCHAR(50),       -- Must prove "Operating Properly"
    system_health_snapshot JSONB,    -- RAM, CPU, Disk health at time of capture
    
    -- PART B: Expert/Chain of Custody
    hash_algorithm VARCHAR(20) DEFAULT 'SHA256',
    output_source_app VARCHAR(255),  -- e.g., "TSI Privacy Vault v1.2"
    captured_by_user_id VARCHAR(100),
    timestamp_ist TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, -- Time in IST 24-hr format
    
    -- Final Certificate Linkage
    is_anchored BOOLEAN DEFAULT TRUE  -- Permanent record for evidence
);

-- 3. Audit Log for Access (Proves Lawful Control)
CREATE TABLE vault_audit_trail (
    audit_id BIGSERIAL PRIMARY KEY,
    reference_key UUID REFERENCES vault_registry(reference_key),
    action_type VARCHAR(20),         -- 'STORE', 'FETCH', 'PRINT'
    api_key VARCHAR(100),            -- App or User ID
    access_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45)
);