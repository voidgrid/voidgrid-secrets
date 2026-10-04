CREATE TABLE users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    auth_method     TEXT NOT NULL CHECK (auth_method IN ('password_totp', 'oidc')),
    password_hash   TEXT,
    totp_secret_enc TEXT,
    totp_secret_nonce TEXT,
    oidc_subject    TEXT,
    disabled        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX idx_users_oidc_subject ON users (oidc_subject) WHERE oidc_subject IS NOT NULL;

CREATE TABLE groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE user_groups (
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    role     TEXT NOT NULL CHECK (role IN ('member', 'admin')),
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE secrets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    owner_type      TEXT NOT NULL CHECK (owner_type IN ('user', 'group')),
    owner_id        INTEGER NOT NULL,
    wrapped_dek     TEXT NOT NULL,
    dek_nonce       TEXT NOT NULL,
    ciphertext      TEXT NOT NULL,
    value_nonce     TEXT NOT NULL,
    key_version     INTEGER NOT NULL DEFAULT 1,
    created_by      INTEGER NOT NULL REFERENCES users(id),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (owner_type, owner_id, name)
);

CREATE TABLE secret_shares (
    secret_id    INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    grantee_type TEXT NOT NULL CHECK (grantee_type IN ('user', 'group')),
    grantee_id   INTEGER NOT NULL,
    permission   TEXT NOT NULL CHECK (permission IN ('read', 'write')),
    granted_by   INTEGER NOT NULL REFERENCES users(id),
    granted_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (secret_id, grantee_type, grantee_id)
);

CREATE TABLE machine_tokens (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash    TEXT NOT NULL UNIQUE,
    description   TEXT NOT NULL DEFAULT '',
    created_by    INTEGER NOT NULL REFERENCES users(id),
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at    TEXT,
    revoked_at    TEXT,
    last_used_at  TEXT
);

CREATE TABLE machine_token_acls (
    token_id      INTEGER NOT NULL REFERENCES machine_tokens(id) ON DELETE CASCADE,
    resource_type TEXT NOT NULL CHECK (resource_type IN ('secret', 'group')),
    resource_id   INTEGER NOT NULL,
    permission    TEXT NOT NULL CHECK (permission IN ('read', 'write')),
    PRIMARY KEY (token_id, resource_type, resource_id)
);

CREATE TABLE audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_type    TEXT NOT NULL CHECK (actor_type IN ('user', 'token')),
    actor_id      INTEGER NOT NULL,
    action        TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id   INTEGER,
    metadata      TEXT NOT NULL DEFAULT '{}',
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE auth_config (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    auth_method TEXT NOT NULL CHECK (auth_method IN ('password_totp', 'oidc')),
    oidc_issuer TEXT,
    oidc_client_id TEXT,
    oidc_client_secret_enc TEXT,
    oidc_client_secret_nonce TEXT,
    completed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
