CREATE TABLE audit_log_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_type    TEXT NOT NULL CHECK (actor_type IN ('user', 'token', 'anonymous', 'system')),
    actor_id      INTEGER NOT NULL,
    action        TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id   INTEGER,
    metadata      TEXT NOT NULL DEFAULT '{}',
    created_at    TEXT NOT NULL
);
INSERT INTO audit_log_new (id, actor_type, actor_id, action, resource_type, resource_id, metadata, created_at)
    SELECT id, actor_type, actor_id, action, resource_type, resource_id, metadata, created_at FROM audit_log;
DROP TABLE audit_log;
ALTER TABLE audit_log_new RENAME TO audit_log;
CREATE INDEX idx_audit_actor ON audit_log (actor_type, actor_id);
CREATE INDEX idx_audit_resource ON audit_log (resource_type, resource_id);
CREATE INDEX idx_audit_action ON audit_log (action);
