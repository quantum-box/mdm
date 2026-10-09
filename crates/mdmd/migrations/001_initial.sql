CREATE TABLE enrollments (
    id TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK (state IN ('pending','authenticated','active','revoked')),
    udid TEXT,
    serial_number TEXT,
    os_version TEXT,
    fingerprint TEXT UNIQUE,
    certificate_expires_at TEXT,
    challenge_hash TEXT NOT NULL UNIQUE,
    challenge_expires_at INTEGER NOT NULL,
    scep_request_hash TEXT,
    scep_response BLOB,
    push_token BLOB,
    push_magic TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX one_live_udid ON enrollments(udid)
    WHERE udid IS NOT NULL AND state != 'revoked';

CREATE TABLE commands (
    id TEXT PRIMARY KEY,
    enrollment_id TEXT NOT NULL REFERENCES enrollments(id),
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('queued','awaiting_response','deferred','completed','failed','outcome_unknown','cancelled')),
    idempotency_key TEXT NOT NULL UNIQUE,
    request_hash TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    result TEXT
);
CREATE INDEX commands_by_generation ON commands(enrollment_id,created_at);
CREATE UNIQUE INDEX one_inflight_command ON commands(enrollment_id) WHERE state='awaiting_response';

CREATE TABLE delivery_attempts (
    command_id TEXT NOT NULL REFERENCES commands(id),
    attempt INTEGER NOT NULL,
    dispatched_at INTEGER NOT NULL,
    PRIMARY KEY(command_id,attempt)
);
CREATE TABLE responses (
    id INTEGER PRIMARY KEY,
    command_id TEXT NOT NULL REFERENCES commands(id),
    attempt INTEGER NOT NULL,
    status TEXT NOT NULL,
    digest TEXT NOT NULL,
    body TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    UNIQUE(command_id,attempt,status,digest)
);
CREATE TABLE outbox (
    id INTEGER PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE REFERENCES commands(id),
    enrollment_id TEXT NOT NULL REFERENCES enrollments(id),
    state TEXT NOT NULL CHECK (state IN ('pending','leased','accepted','rejected','cancelled')),
    available_at INTEGER NOT NULL,
    lease_until INTEGER,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_reason TEXT,
    apns_id TEXT
);
CREATE TABLE notification_attempts (
    id INTEGER PRIMARY KEY,
    outbox_id INTEGER NOT NULL REFERENCES outbox(id),
    attempted_at INTEGER NOT NULL,
    outcome TEXT NOT NULL,
    reason TEXT,
    apns_id TEXT
);
CREATE TABLE audit (
    id INTEGER PRIMARY KEY,
    happened_at INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_id TEXT NOT NULL
);
PRAGMA user_version = 1;
