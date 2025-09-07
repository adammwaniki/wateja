-- services/database/init/init.sql for docker compose
-- Create both databases
CREATE DATABASE IF NOT EXISTS watejaUsers;
CREATE DATABASE IF NOT EXISTS wateja_sessions;

-- Initialize watejaUsers database with user tables
USE watejaUsers;

CREATE TABLE IF NOT EXISTS users(
    internal_id BIGINT UNSIGNED PRIMARY KEY,
    external_id BINARY(16) UNIQUE NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    email VARCHAR(320) NOT NULL UNIQUE,
    password_hash VARCHAR(255) BINARY NULL,
    sso_id VARCHAR(255) NULL,
    status ENUM(
        'STATUS_UNSPECIFIED',
        'ACTIVE',
        'SUSPENDED',
        'PENDING',
        'CLOSED'
        ) NOT NULL DEFAULT 'ACTIVE',
    terms_accepted_at DATETIME NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(6)
);

-- Initialize wateja_sessions database with session tables
USE wateja_sessions;

CREATE TABLE IF NOT EXISTS user_sessions (
    session_id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    access_token_id VARCHAR(36) NOT NULL UNIQUE,
    refresh_token_id VARCHAR(36) NOT NULL UNIQUE,
    user_agent TEXT,
    ip_address VARCHAR(45),
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_accessed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at DATETIME(6) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at DATETIME(6) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(6),
    
    INDEX idx_user_sessions_user_id (user_id),
    INDEX idx_user_sessions_access_token_id (access_token_id),
    INDEX idx_user_sessions_refresh_token_id (refresh_token_id),
    INDEX idx_user_sessions_expires_at (expires_at),
    INDEX idx_user_sessions_is_active (is_active),
    INDEX idx_user_sessions_last_accessed (last_accessed_at)
);