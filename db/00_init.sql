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
    recovery_hash TEXT,
    recovery_salt TEXT,
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
    entity_ref UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type VARCHAR(20) NOT NULL, -- 'ID' or 'FILE'
    id_type_code VARCHAR(50),        -- Aadhaar, Voter, etc. (for IDs)
    file_name TEXT,                  -- Original name (for Files)
    encrypted_content TEXT NOT NULL, -- The "Locked Box" (Encrypted Data)
    encrypted_data_key TEXT,         -- The "Locked Key" (Wrapped DEK)
    hashed_value_sha256 CHAR(64) NOT NULL, -- MANDATORY for BSA Part B
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create the Inverted Index Table
CREATE TABLE vault_search_index (
    index_id SERIAL PRIMARY KEY,
    
    -- The deterministic SHA-256 hash of the PII attribute (Blind Index)
    index_hash VARCHAR(64) NOT NULL,
    
    -- Foreign key linking to the actual encrypted record in vault_entities
    entity_ref UUID NOT NULL,
    
    -- Metadata to identify what part of the PII this hash represents
    -- Examples: 'FULL', 'PART' (for name segments), 'PREFIX' (for mobile/IDs)
    attribute_type VARCHAR(20),
    
    -- Forensic timestamp for BSA 2023 compliance
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_vault_entity 
        FOREIGN KEY(entity_ref) 
        REFERENCES vault_entities(entity_ref) 
        ON DELETE CASCADE
);

CREATE TABLE vault_utilities (
    utility_ref UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    flavor VARCHAR(20) NOT NULL, -- KEYS, CERT, SHARED_KEYS
    label VARCHAR(255) NOT NULL UNIQUE,
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

-- Create Table: event_log
CREATE TABLE IF NOT EXISTS event_log (
    log_id BIGSERIAL PRIMARY KEY,    
    who VARCHAR(255),    
    operation_type VARCHAR(255) NOT NULL,    
    entity_code VARCHAR(50), 
    entity_ref UUID,      -- Used by the Entity Master
    utility_ref UUID, -- Used by the Utility 
    client_ip VARCHAR(45) NOT NULL, 
    user_agent TEXT,                
    machine_id VARCHAR(100),       
    outcome VARCHAR(20) DEFAULT 'SUCCESS' 
        CHECK (outcome IN ('SUCCESS', 'DENIED', 'ERROR')),
    failure_reason TEXT,           
    log_datetime TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);


-- Indexes

-- Critical for isAuthorized() checks and permission resolution
CREATE UNIQUE INDEX idx_permissions_composite ON permissions(api_key, resource_id, resource_type);

-- Supports listing all keys by creation date for the dashboard
CREATE INDEX idx_api_user_created ON api_user(created_datetime DESC);

-- Support for the Inverted Index (Deterministic Blind Index)
CREATE INDEX idx_search_index_hash ON vault_search_index(index_hash);
CREATE INDEX idx_search_index_ref ON vault_search_index(entity_ref);

-- Unique index for the master record retrieval
CREATE UNIQUE INDEX idx_vault_entities_ref ON vault_entities(entity_ref);

-- Supports entity master lookups and active flavor checks
CREATE UNIQUE INDEX idx_vault_master_code ON vault_entity_master(entity_code);

-- Supports utility resolution by label (API ID)
CREATE INDEX idx_vault_utilities_label ON vault_utilities(label, active) WHERE active = true;

-- Supports utility lookup by UUID reference
CREATE UNIQUE INDEX idx_vault_utilities_ref ON vault_utilities(utility_ref);

