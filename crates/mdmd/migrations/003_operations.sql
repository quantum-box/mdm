ALTER TABLE enrollments ADD COLUMN expected_serial TEXT;
ALTER TABLE enrollments ADD COLUMN expected_udid TEXT;
ALTER TABLE enrollments ADD COLUMN awaiting_configuration INTEGER NOT NULL DEFAULT 0;
ALTER TABLE enrollments ADD COLUMN mdm_access_rights INTEGER NOT NULL DEFAULT 19;
CREATE TABLE device_observations (
    enrollment_id TEXT NOT NULL REFERENCES enrollments(id),
    category TEXT NOT NULL,
    command_id TEXT NOT NULL REFERENCES commands(id),
    dispatched_at INTEGER NOT NULL,
    dispatch_order INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    body TEXT NOT NULL,
    PRIMARY KEY(enrollment_id,category)
);
CREATE TABLE erase_intents (
    id TEXT PRIMARY KEY,
    enrollment_id TEXT NOT NULL REFERENCES enrollments(id),
    token_hash TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    command_id TEXT REFERENCES commands(id)
);
CREATE TABLE ade_devices (
    serial_number TEXT PRIMARY KEY,
    profile_uuid TEXT,
    op_type TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    body TEXT NOT NULL
);
CREATE TABLE apple_requests (
    idempotency_key TEXT PRIMARY KEY,
    request_hash TEXT NOT NULL,
    operation TEXT NOT NULL,
    state TEXT NOT NULL,
    result TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE app_license_assignments (
    adam_id INTEGER NOT NULL,
    serial_number TEXT NOT NULL,
    assigned INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    body TEXT NOT NULL,
    PRIMARY KEY(adam_id,serial_number)
);
CREATE TABLE ade_profiles (profile_uuid TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE ade_bootstrap (serial_number TEXT PRIMARY KEY, enrollment_id TEXT NOT NULL REFERENCES enrollments(id), request_hash TEXT NOT NULL, profile BLOB NOT NULL, expires_at INTEGER NOT NULL);
PRAGMA user_version = 3;
