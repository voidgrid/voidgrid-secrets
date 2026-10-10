-- Secret groups are a convenience for the web UI only: a named set of
-- secrets to tick together when editing a token's grants. Grants, tokens
-- and the /env endpoint never reference them.
CREATE TABLE secret_groups (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    created_at TEXT NOT NULL
);

CREATE TABLE secret_group_members (
    group_id  INTEGER NOT NULL REFERENCES secret_groups(id) ON DELETE CASCADE,
    secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, secret_id)
);

CREATE INDEX idx_group_members_secret ON secret_group_members (secret_id);
