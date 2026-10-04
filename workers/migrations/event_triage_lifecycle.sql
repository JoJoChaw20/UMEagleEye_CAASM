-- Alert triage lifecycle + analyst-confirmed internet exposure.
--
-- Adds status/assignment/first-seen/last-seen tracking to events so alerts can
-- be worked and closed instead of deleted, and collapses the duplicate drift
-- events the old 24-hour dedup window produced.
--
-- Safe to re-run. Run this BEFORE deploying the new Workers code.

BEGIN;

-- ── 1. Event status enum ─────────────────────────────────────────
DO $$ BEGIN
  CREATE TYPE event_status AS ENUM ('open', 'in_progress', 'resolved', 'false_positive', 'accepted_risk');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ── 2. Lifecycle columns on events ───────────────────────────────
ALTER TABLE events ADD COLUMN IF NOT EXISTS status          event_status NOT NULL DEFAULT 'open';
ALTER TABLE events ADD COLUMN IF NOT EXISTS assigned_to     uuid REFERENCES users(user_id) ON DELETE SET NULL;
ALTER TABLE events ADD COLUMN IF NOT EXISTS first_seen      timestamptz  NOT NULL DEFAULT now();
ALTER TABLE events ADD COLUMN IF NOT EXISTS last_seen       timestamptz  NOT NULL DEFAULT now();
ALTER TABLE events ADD COLUMN IF NOT EXISTS occurrences     integer      NOT NULL DEFAULT 1;
ALTER TABLE events ADD COLUMN IF NOT EXISTS resolved_at     timestamptz;
ALTER TABLE events ADD COLUMN IF NOT EXISTS resolved_by     uuid REFERENCES users(user_id) ON DELETE SET NULL;
ALTER TABLE events ADD COLUMN IF NOT EXISTS resolution_note text;
ALTER TABLE events ADD COLUMN IF NOT EXISTS updated_at      timestamptz  NOT NULL DEFAULT now();

CREATE INDEX IF NOT EXISTS idx_events_status       ON events (status);
CREATE INDEX IF NOT EXISTS idx_events_asset_status ON events (asset_id, status);

-- Existing rows: first/last seen = when they were raised
UPDATE events SET first_seen = timestamp, last_seen = timestamp
WHERE first_seen > timestamp;

-- ── 3. Collapse duplicate open drift events ──────────────────────
-- The old dedup only looked back 24h, so a persistent drift (e.g. a port that
-- stays open) raised a new event every day. Keep the newest event per
-- (asset, type, key) open, roll the count/first-seen into it, and close the
-- older copies as resolved — nothing is deleted, so advisories stay intact.
WITH keyed AS (
  SELECT event_id, asset_id, event_type, timestamp,
         concat_ws('::', asset_id, event_type,
                   details->>'port', details->>'changed_attribute', details->>'package') AS dedup_key
  FROM events
  WHERE status = 'open'
    AND event_type IN ('port_opened','port_closed','version_downgrade','version_upgrade',
                       'config_change','new_package','removed_package')
),
ranked AS (
  SELECT event_id, dedup_key,
         row_number() OVER (PARTITION BY dedup_key ORDER BY timestamp DESC) AS rn,
         count(*)     OVER (PARTITION BY dedup_key)                         AS n,
         min(timestamp) OVER (PARTITION BY dedup_key)                       AS first_ts
  FROM keyed
),
keep AS (
  UPDATE events e SET occurrences = r.n, first_seen = r.first_ts
  FROM ranked r
  WHERE e.event_id = r.event_id AND r.rn = 1 AND r.n > 1
  RETURNING e.event_id
)
UPDATE events e
SET status = 'resolved',
    resolved_at = now(),
    resolution_note = 'Merged into newer duplicate during triage migration'
FROM ranked r
WHERE e.event_id = r.event_id AND r.rn > 1;

-- ── 4. Analyst-confirmed internet exposure on assets ─────────────
ALTER TABLE assets ADD COLUMN IF NOT EXISTS internet_facing_override boolean;

COMMIT;
