CREATE TABLE declarations (
    identifier TEXT PRIMARY KEY,
    category TEXT NOT NULL,
    server_token TEXT NOT NULL,
    body TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1)),
    updated_at INTEGER NOT NULL
);
CREATE TABLE declaration_revisions (
    identifier TEXT NOT NULL REFERENCES declarations(identifier),
    server_token TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(identifier,server_token)
);
CREATE TABLE ddm_state (
    enrollment_id TEXT PRIMARY KEY REFERENCES enrollments(id),
    declarations_token TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE declaration_targets (
    identifier TEXT NOT NULL REFERENCES declarations(identifier),
    enrollment_id TEXT NOT NULL REFERENCES ddm_state(enrollment_id),
    PRIMARY KEY(identifier,enrollment_id)
);
CREATE TABLE ddm_reports (
    id INTEGER PRIMARY KEY,
    enrollment_id TEXT NOT NULL REFERENCES ddm_state(enrollment_id),
    digest TEXT NOT NULL,
    body TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    UNIQUE(enrollment_id,digest)
);
CREATE INDEX ddm_reports_by_generation ON ddm_reports(enrollment_id,id);
PRAGMA user_version = 2;
