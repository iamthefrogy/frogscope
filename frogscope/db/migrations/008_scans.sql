-- Provenance for runs that came from a scan we ran ourselves.
--
-- Recorded so a run is self-describing: which domains, which port profile, which
-- httpx flags. Without it, "why does this run have fewer endpoints than the last
-- one?" has no answer six months later — and the most common cause is a narrower
-- port profile, not a change in the estate.
--
-- `source_kind` distinguishes the two paths. Both produce identical runs, which is
-- the point, but knowing which is which matters when a scan looks truncated.

ALTER TABLE runs ADD COLUMN source_kind TEXT NOT NULL DEFAULT 'upload';
ALTER TABLE runs ADD COLUMN scan_json   TEXT;
