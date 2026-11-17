PRAGMA foreign_keys = ON;

CREATE TABLE keys (
  id TEXT PRIMARY KEY,
  service TEXT NOT NULL,
  label TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  nonce TEXT NOT NULL,
  enc_version INTEGER NOT NULL CHECK(enc_version IN (1,2)),
  policy_json TEXT NOT NULL CHECK(json_valid(policy_json)),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  UNIQUE(service,label)
);
CREATE TABLE agents (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE CHECK(length(token_hash)=64 AND token_hash NOT GLOB '*[^0-9a-f]*'),
  policy_json TEXT NOT NULL CHECK(json_valid(policy_json)),
  revoked_at INTEGER
);
CREATE TABLE grants (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id),
  key_id TEXT NOT NULL REFERENCES keys(id),
  service TEXT NOT NULL,
  policy_json TEXT NOT NULL CHECK(json_valid(policy_json)),
  opened_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK(expires_at=opened_at+7200),
  revoked_at INTEGER,
  admin_request_id TEXT NOT NULL UNIQUE
);
CREATE INDEX grants_agent_key_expiry ON grants(agent_id,key_id,expires_at);
CREATE TRIGGER grant_service_insert BEFORE INSERT ON grants
WHEN NOT EXISTS(SELECT 1 FROM keys WHERE id=NEW.key_id AND service=NEW.service)
BEGIN SELECT RAISE(ABORT,'key service mismatch'); END;
CREATE TRIGGER grant_service_update BEFORE UPDATE OF key_id,service ON grants
WHEN NOT EXISTS(SELECT 1 FROM keys WHERE id=NEW.key_id AND service=NEW.service)
BEGIN SELECT RAISE(ABORT,'key service mismatch'); END;
CREATE TRIGGER key_identity_immutable BEFORE UPDATE OF id,service,label ON keys
BEGIN SELECT RAISE(ABORT,'key identity immutable'); END;

CREATE TABLE audit (
  id TEXT PRIMARY KEY,
  ts INTEGER NOT NULL,
  agent_id TEXT,
  key_id TEXT,
  grant_id TEXT,
  operation TEXT NOT NULL,
  status TEXT NOT NULL,
  request_id TEXT NOT NULL
);
CREATE INDEX audit_ts ON audit(ts);
-- Atomic capacity guard. Refuse before changes if maintenance cannot reclaim space.
CREATE TRIGGER audit_capacity BEFORE INSERT ON audit
WHEN (SELECT count(*) FROM audit)>=10000
  OR (SELECT count(*) FROM audit WHERE ts>=NEW.ts-(NEW.ts%86400))>=1000
BEGIN SELECT RAISE(ABORT,'audit capacity'); END;

-- No payloads or upstream responses. Never redispatch an existing reservation.
CREATE TABLE write_operations (
  agent_id TEXT NOT NULL REFERENCES agents(id),
  request_id TEXT NOT NULL,
  key_id TEXT NOT NULL REFERENCES keys(id),
  fingerprint TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('reserved','succeeded','failed','unknown')),
  created_at INTEGER NOT NULL,
  PRIMARY KEY(agent_id,request_id)
);
CREATE INDEX write_operations_created ON write_operations(created_at);
CREATE TRIGGER write_capacity BEFORE INSERT ON write_operations
WHEN (SELECT count(*) FROM write_operations)>=10000
BEGIN SELECT RAISE(ABORT,'write capacity'); END;
-- Bounded admin idempotency tombstones. Unlock uses grants.admin_request_id instead.
CREATE TABLE admin_requests (
  request_id TEXT PRIMARY KEY,
  operation TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TRIGGER admin_capacity BEFORE INSERT ON admin_requests
WHEN (SELECT count(*) FROM admin_requests)>=10000
BEGIN SELECT RAISE(ABORT,'admin capacity'); END;
