CREATE TABLE users (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    username          TEXT NOT NULL,
    auth_method       TEXT NOT NULL CHECK (auth_method IN ('password_totp', 'oidc')),
    password_hash     TEXT,
    totp_secret_enc   TEXT,
    totp_secret_nonce TEXT,
    totp_last_code    TEXT,
    oidc_subject      TEXT,
    created_at        TEXT NOT NULL
);

CREATE TABLE auth_config (
    id                       INTEGER PRIMARY KEY CHECK (id = 1),
    auth_method              TEXT NOT NULL CHECK (auth_method IN ('password_totp', 'oidc')),
    oidc_issuer              TEXT,
    oidc_client_id           TEXT,
    oidc_client_secret_enc   TEXT,
    oidc_client_secret_nonce TEXT,
    oidc_redirect_uri        TEXT,
    completed_at             TEXT
);

CREATE TABLE sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_hash TEXT NOT NULL UNIQUE,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    revoked_at   TEXT
);

CREATE TABLE recovery_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL UNIQUE,
    used_at    TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE account_resets (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    source            TEXT NOT NULL CHECK (source IN ('recovery_code', 'break_glass')),
    code_hash         TEXT NOT NULL UNIQUE,
    stage             TEXT NOT NULL CHECK (stage IN ('issued', 'started')),
    totp_secret_enc   TEXT,
    totp_secret_nonce TEXT,
    expires_at        TEXT NOT NULL,
    used_at           TEXT,
    created_at        TEXT NOT NULL
);

CREATE TABLE secrets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    wrapped_dek TEXT NOT NULL,
    dek_nonce   TEXT NOT NULL,
    ciphertext  TEXT NOT NULL,
    value_nonce TEXT NOT NULL,
    key_version INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE machine_tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash   TEXT NOT NULL UNIQUE,
    description  TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    expires_at   TEXT,
    revoked_at   TEXT,
    last_used_at TEXT
);

CREATE TABLE machine_token_grants (
    token_id   INTEGER NOT NULL REFERENCES machine_tokens(id) ON DELETE CASCADE,
    secret_id  INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    permission TEXT NOT NULL CHECK (permission IN ('read', 'write')),
    env_name   TEXT,
    PRIMARY KEY (token_id, secret_id)
);

CREATE TABLE audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_type    TEXT NOT NULL CHECK (actor_type IN ('user', 'token', 'anonymous', 'system')),
    actor_id      INTEGER NOT NULL,
    action        TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id   INTEGER,
    metadata      TEXT NOT NULL DEFAULT '{}',
    created_at    TEXT NOT NULL
);

CREATE INDEX idx_audit_created_at ON audit_log (created_at);
CREATE INDEX idx_audit_action ON audit_log (action);
