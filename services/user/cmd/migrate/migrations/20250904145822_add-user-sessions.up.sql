-- services/user/cmd/migrate/migrations/20250904145822_add-user-sessions.up.sql
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    access_token_id VARCHAR(36) NOT NULL UNIQUE,
    refresh_token_id VARCHAR(36) NOT NULL UNIQUE,
    user_agent TEXT,
    ip_address VARCHAR(45), -- IPv6 compatible
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
