-- services/user/cmd/migrate/migrations/20250902152435_add-user-table.up.sql
CREATE TABLE IF NOT EXISTS users(
    internal_id BIGINT UNSIGNED PRIMARY KEY,
    external_id BINARY(16) UNIQUE NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    email VARCHAR(320) NOT NULL UNIQUE,
    password_hash VARCHAR(255) BINARY NULL, -- Allow NULL for SSO users, use BINARY for case-sensitive match
    sso_id VARCHAR(255) NULL,
    status ENUM(
        'STATUS_UNSPECIFIED',
        'ACTIVE',
        'SUSPENDED',
        'PENDING',
        'CLOSED'
        ) NOT NULL DEFAULT 'ACTIVE',
    terms_accepted_at DATETIME NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),  -- Microsecond precision
    updated_at DATETIME(6) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(6)
);


