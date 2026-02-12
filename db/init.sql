-- init.sql
-- SQL script for initializing the PostgreSQL database schema for TSI Privacy Vault.

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

CREATE TABLE vault_entity_master (
    -- Primary Identifiers
    entity_code VARCHAR(50) PRIMARY KEY, -- e.g., 'AADHAAR', 'MRI_SCAN', 'HOME_ADDR'
    entity_name VARCHAR(255) NOT NULL,    
    -- Flavor Classification
    flavor VARCHAR(10) CHECK (flavor IN ('ID', 'DATA', 'FILE')),      
    -- Validation & Processing
    validation_regex TEXT, -- For ID and DATA strings
    mime_types TEXT,      -- For FILE flavors (e.g., 'application/pdf')
    max_size_kb INTEGER,  -- Limit for FILE uploads
    -- Forensic Requirements (BSA 2023)
    hashing_algorithm VARCHAR(20) DEFAULT 'SHA-256', 
    is_forensic_required BOOLEAN DEFAULT TRUE,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create Table: api_user
CREATE TABLE api_user (
    api_key VARCHAR(255) PRIMARY KEY,
    api_secret VARCHAR(255) NOT NULL,
    client_name VARCHAR(255) NOT NULL UNIQUE,
    active BOOLEAN DEFAULT TRUE,
    created_datetime TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE api_user_permissions (
    permission_id SERIAL PRIMARY KEY,    
    -- The Actor: Which app/user is this for?
    api_key VARCHAR(255) REFERENCES api_user(api_key) ON DELETE CASCADE,
    -- The Resource: What specific data can they touch?
    entity_code VARCHAR(50) REFERENCES vault_entity_master(entity_code) ON DELETE CASCADE,
    -- The Action: What can they do?
    can_read BOOLEAN DEFAULT FALSE,
    can_write BOOLEAN DEFAULT FALSE,
    -- Optional: Audit metadata for the permission itself
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    granted_by VARCHAR(255) -- Track which admin gave this access
);

-- Master Table for ID and File Records
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

-- BSA 2023 Forensic Metadata (The "Evidence Log")
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

-- Audit Log for Access (Proves Lawful Control)
CREATE TABLE vault_audit_trail (
    audit_id BIGSERIAL PRIMARY KEY,
    reference_key UUID REFERENCES vault_registry(reference_key),
    action_type VARCHAR(20),         -- 'STORE', 'FETCH', 'PRINT'
    api_key VARCHAR(100),            -- App or User ID
    access_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45)
);

-- Create Table: event_log
CREATE TABLE event_log (
    -- Unique Identifier for the log entry
    log_id BIGSERIAL PRIMARY KEY,    
    -- The "Who": Application or User Identity
    api_key VARCHAR(255) REFERENCES api_user(api_key),    
    -- The "What": Action performed (e.g., STORE, FETCH, LOOKUP, DELETE)
    operation_type VARCHAR(50) NOT NULL,    
    -- The "Flavor": Links to the blueprint (ID/DATA/FILE)
    entity_code VARCHAR(50) REFERENCES vault_entity_master(entity_code),    
    -- The "Specific Record": Pointer to the vaulted item
    reference_key UUID REFERENCES vault_registry(reference_key),    
    -- The "Where": Network and Device Identity
    client_ip VARCHAR(45) NOT NULL, -- IPv4 or IPv6
    user_agent TEXT,                -- Browser/SDK version
    machine_id VARCHAR(100),       -- Serial/MAC for BSA Part A    
    -- The "Result": Success or Failure (for RBAC auditing)
    outcome VARCHAR(20) DEFAULT 'SUCCESS' 
        CHECK (outcome IN ('SUCCESS', 'DENIED', 'ERROR')),
    failure_reason TEXT,           -- e.g., "RBAC Violation", "Invalid Hash"    
    -- The "When": Temporal anchoring
    log_datetime TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);


-- indexes
ALTER TABLE api_user_permissions ADD CONSTRAINT unique_api_permission UNIQUE (api_key, entity_code);