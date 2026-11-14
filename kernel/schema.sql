-- Security Harness — Kernel DB Schema (SQLite)
-- Source of truth for the whole run. Only the kernel writes to these tables.
-- Mirrors PROJECT.md §9 (State Model).

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- One row per harness run.
CREATE TABLE IF NOT EXISTS runs (
    run_id         TEXT PRIMARY KEY,
    target         TEXT NOT NULL,
    contract_hash  TEXT NOT NULL,       -- hash of the frozen scope contract
    profile        TEXT,                -- e.g. "idor-bola-only"
    budget_json    TEXT NOT NULL,       -- serialized budget (hunter/validator caps)
    status         TEXT NOT NULL DEFAULT 'in_progress'
        CHECK (status IN ('in_progress', 'complete', 'incomplete')),
    reason         TEXT,                -- set when status = 'incomplete'
    started_at     TEXT NOT NULL,
    ended_at       TEXT
);

-- Test identities (attacker / victim / baseline). cred_ref is a handle,
-- NEVER the actual token/secret. The broker resolves cred_ref -> secret.
CREATE TABLE IF NOT EXISTS identities (
    id         TEXT PRIMARY KEY,
    run_id     TEXT NOT NULL REFERENCES runs(run_id),
    role       TEXT NOT NULL,           -- "attacker" | "victim" | "baseline" | ...
    label      TEXT NOT NULL,           -- human-readable, e.g. "user_B"
    cred_ref   TEXT NOT NULL            -- opaque ref the broker resolves
);

-- Recon graph: objects/endpoints discovered by the Surface Mapper.
CREATE TABLE IF NOT EXISTS objects (
    id             TEXT PRIMARY KEY,
    run_id         TEXT NOT NULL REFERENCES runs(run_id),
    resource_type  TEXT NOT NULL,       -- "order", "user", "file", ...
    owner_identity TEXT REFERENCES identities(id),
    endpoint       TEXT NOT NULL,
    method         TEXT NOT NULL
);

-- Unit of coverage: one (object, action, identity) cell the harness must
-- plan, hunt, and resolve. This is what proves COMPLETENESS, not just activity.
CREATE TABLE IF NOT EXISTS coverage_units (
    id          TEXT PRIMARY KEY,
    run_id      TEXT NOT NULL REFERENCES runs(run_id),
    object_id   TEXT NOT NULL REFERENCES objects(id),
    action      TEXT NOT NULL,
    identity_id TEXT NOT NULL REFERENCES identities(id),
    state       TEXT NOT NULL DEFAULT 'planned'
        CHECK (state IN ('planned', 'in_progress', 'covered', 'candidate', 'blocked', 'deferred')),
    owner_agent TEXT,                   -- agent/worker id currently holding it
    wave        INTEGER NOT NULL DEFAULT 1
);

-- A candidate finding proposed by a Hunter, before/after grounding + validation.
-- fingerprint = root-cause hash, stable ACROSS runs. Dedup is per run (the
-- composite key), so a re-run still reports a known bug, flagged as known.
CREATE TABLE IF NOT EXISTS candidates (
    fingerprint        TEXT NOT NULL,
    run_id              TEXT NOT NULL REFERENCES runs(run_id),
    unit_id             TEXT NOT NULL REFERENCES coverage_units(id),
    title               TEXT NOT NULL,
    trace_json          TEXT NOT NULL,      -- the claimed request/response sequence
    proposed_verdict    TEXT,
    status              TEXT NOT NULL DEFAULT 'proposed'
        CHECK (status IN ('proposed', 'grounded', 'validated', 'confirmed', 'needs_validation', 'rejected')),
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    PRIMARY KEY (run_id, fingerprint)
);

-- THE GROUNDING LEDGER. Every exact broker exchange, hashed. This is the
-- anti-hallucination spine — a candidate with no matching row here is
-- auto-rejected (enforced by a JOIN, see pre_candidate_accept hook).
CREATE TABLE IF NOT EXISTS ledger (
    id            TEXT PRIMARY KEY,
    run_id        TEXT NOT NULL REFERENCES runs(run_id),
    request_hash  TEXT NOT NULL,
    method        TEXT NOT NULL,
    url           TEXT NOT NULL,
    status_code   INTEGER,
    resp_digest   TEXT,                 -- sha256 of response body
    identity_id   TEXT REFERENCES identities(id),
    ts            TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ledger_request_hash ON ledger(request_hash);
CREATE INDEX IF NOT EXISTS idx_ledger_run ON ledger(run_id);

-- DISPATCH LOG: every request the kernel was asked to send, written BEFORE
-- the broker is called. If the broker crashes or times out mid-request, the
-- attempt is still on record. The ledger says what came back; this says
-- what was attempted, blocked, or lost.
CREATE TABLE IF NOT EXISTS dispatches (
    id          TEXT PRIMARY KEY,
    run_id      TEXT NOT NULL REFERENCES runs(run_id),
    plan_id     TEXT NOT NULL,
    unit_id     TEXT,
    identity    TEXT NOT NULL,         -- label, never a secret
    method      TEXT NOT NULL,
    path        TEXT NOT NULL,
    outcome     TEXT NOT NULL
        CHECK (outcome IN ('vetoed', 'over_budget', 'sent', 'recorded', 'broker_error', 'record_mismatch')),
    ledger_id   TEXT REFERENCES ledger(id),
    detail      TEXT,
    ts          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dispatches_run ON dispatches(run_id);

-- Final, reported findings. Severity only ever set once status = confirmed.
CREATE TABLE IF NOT EXISTS findings (
    fingerprint    TEXT NOT NULL,
    run_id         TEXT NOT NULL REFERENCES runs(run_id),
    verdict        TEXT NOT NULL
        CHECK (verdict IN ('confirmed', 'needs_validation', 'rejected')),
    severity       TEXT,                -- NULL unless verdict = confirmed
    evidence_refs  TEXT NOT NULL,        -- JSON list of ledger ids (minimized trace)
    cleanup_done   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id, fingerprint),
    FOREIGN KEY (run_id, fingerprint) REFERENCES candidates(run_id, fingerprint)
);

-- Dead-worker recovery. A lease that lapses is reclaimed, never assumed done.
CREATE TABLE IF NOT EXISTS leases (
    unit_id     TEXT PRIMARY KEY REFERENCES coverage_units(id),
    agent_id    TEXT NOT NULL,
    expires_at  TEXT NOT NULL
);

-- RESEARCH STATE (curated — distinct from the ledger, which saves everything).
CREATE TABLE IF NOT EXISTS threads (
    id                TEXT PRIMARY KEY,
    run_id            TEXT NOT NULL REFERENCES runs(run_id),
    unit_id           TEXT REFERENCES coverage_units(id),
    hypothesis        TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'holding', 'rejected', 'confirmed')),
    next_step         TEXT,
    rejected_paths    TEXT,             -- JSON list: dead ends already tried
    reopen_condition  TEXT,             -- what new fact would reopen this
    assumptions       TEXT,             -- JSON
    env_conditions    TEXT              -- JSON
);

-- THE THREAD INDEX: links a hypothesis to the exact ledger rows behind it.
-- This is the retrieval path — a fresh agent reads this, not raw scrollback.
CREATE TABLE IF NOT EXISTS thread_evidence (
    thread_id  TEXT NOT NULL REFERENCES threads(id),
    ledger_id  TEXT NOT NULL REFERENCES ledger(id),
    note       TEXT,
    PRIMARY KEY (thread_id, ledger_id)
);
