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

-- Master Table for ID, DATA and File Records
CREATE TABLE vault_entities (
    reference_key UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type VARCHAR(20) NOT NULL, -- 'ID' or 'FILE'
    id_type_code VARCHAR(50),        -- Aadhaar, Voter, etc. (for IDs)
    file_name TEXT,                  -- Original name (for Files)
    encrypted_content TEXT NOT NULL, -- The "Locked Box" (Encrypted Data)
    encrypted_data_key TEXT,         -- The "Locked Key" (Wrapped DEK)
    hashed_value_sha256 CHAR(64) NOT NULL, -- MANDATORY for BSA Part B
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE vault_utilities (
    utility_id VARCHAR(50) PRIMARY KEY,
    flavor VARCHAR(20) NOT NULL, -- KEYS, CERT, SHARED_KEYS
    label VARCHAR(255) NOT NULL,
    payload TEXT, -- Encrypted local secret
    metadata JSONB NOT NULL DEFAULT '{}', -- stores external_ref, alias, passphrase, k, n
    encrypted_key TEXT,  
    machine_id VARCHAR(50) NOT NULL, -- Mandatory hardware anchor
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- API Permissions Schema
CREATE TABLE permissions (
    permission_id SERIAL PRIMARY KEY,
    
    -- THE ACTOR
    -- References the unique API Key of the application or agent
    api_key VARCHAR(255) NOT NULL REFERENCES api_user(api_key) ON DELETE CASCADE,
    
    -- THE RESOURCE
    -- 'ENTITY' for broad access to a business unit
    -- 'UTILITY' for granular access to a specific secret
    resource_type VARCHAR(20) NOT NULL CHECK (resource_type IN ('ENTITY', 'UTILITY')),
    
    -- Holds the entity_code or utility_id
    resource_id TEXT NOT NULL,

    -- THE ACTIONS
    -- can_read: Permission to retrieve cleartext
    -- can_write: Permission to enroll, update, or rotate keys
    can_read BOOLEAN DEFAULT FALSE,
    can_write BOOLEAN DEFAULT FALSE,

    -- AUDIT METADATA
    -- Essential for BSA Section 62 (Forensic Evidence)
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    granted_by VARCHAR(255), 
    
    -- Prevent duplicate rule definitions
    UNIQUE(api_key, resource_type, resource_id)
);

-- BSA 2023 Forensic Metadata (The "Evidence Log")
CREATE TABLE bsa_forensic_logs (
    log_id BIGSERIAL PRIMARY KEY,
    reference_key UUID,    
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


-- Create Table: event_log
CREATE TABLE IF NOT EXISTS event_log (
    log_id BIGSERIAL PRIMARY KEY,    
    who VARCHAR(255),    
    operation_type VARCHAR(50) NOT NULL,    
    entity_code VARCHAR(50), 
    reference_key UUID,      -- Used by the Entity Master
    utility_ref UUID, -- Used by the Utility 
    client_ip VARCHAR(45) NOT NULL, 
    user_agent TEXT,                
    machine_id VARCHAR(100),       
    outcome VARCHAR(20) DEFAULT 'SUCCESS' 
        CHECK (outcome IN ('SUCCESS', 'DENIED', 'ERROR')),
    failure_reason TEXT,           
    log_datetime TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

