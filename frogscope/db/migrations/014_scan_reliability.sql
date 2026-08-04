-- What a scan actually submitted to httpx, and whether naabu managed to
-- scope it -- without this, drift_check can only compare endpoint_count
-- between two runs and cannot tell "the same ~300 domains produced fewer
-- rows this time" (a truncated run) apart from "fewer domains were
-- submitted this time" (a legitimately smaller estate) or "naabu fell back
-- to the full port profile" (a known, explained cause of a different
-- count). NULL for uploads and every run ingested before this migration --
-- those fall back to the plain count-only drift check unchanged.

ALTER TABLE runs ADD COLUMN hosts_submitted INTEGER;
ALTER TABLE runs ADD COLUMN ports_prescoped INTEGER;
