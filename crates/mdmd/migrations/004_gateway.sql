CREATE TABLE gateway_nonces (
    nonce TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);
PRAGMA user_version = 4;
