-- D1 schema for the Foundry marketplace Worker.

-- Per-author daily submission counter (protects the AI review budget — the real DoS surface).
CREATE TABLE IF NOT EXISTS rate (
  author TEXT NOT NULL,
  day    INTEGER NOT NULL, -- unix-ms at start of the UTC day
  count  INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (author, day)
);

-- Submissions the AI review flagged for a human decision (never auto-published).
CREATE TABLE IF NOT EXISTS flagged (
  id           TEXT NOT NULL,    -- author/name
  version      TEXT NOT NULL,
  submitted_at INTEGER NOT NULL,
  verdict      TEXT NOT NULL,    -- the full JSON verdict
  PRIMARY KEY (id, version)
);
