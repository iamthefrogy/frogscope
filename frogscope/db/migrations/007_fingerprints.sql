-- Passive product identification.
--
-- Typed columns rather than a JSON blob, because "show me every exposed CI/CD
-- console, sorted by risk" has to be a server-side query. An attribute bag would
-- force the whole estate into the browser to answer it.
--
-- These say WHAT was identified. Whether it matters is decided by rules.yaml, and
-- keeping the two apart is what lets each be argued about on its own.

ALTER TABLE endpoints ADD COLUMN panel_product      TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN panel_group        TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN panel_exposure     TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN panel_confidence   TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN panel_count        INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN is_default_page    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN default_page_product TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN disclosure_count   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN disclosure_worst   TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN fingerprint_count  INTEGER NOT NULL DEFAULT 0;

-- The queries the panel views actually run: "every console of this kind in this
-- run, worst first".
CREATE INDEX IF NOT EXISTS idx_ep_panel_group
    ON endpoints(run_id, panel_group);
CREATE INDEX IF NOT EXISTS idx_ep_panel_exposure
    ON endpoints(run_id, panel_exposure);
CREATE INDEX IF NOT EXISTS idx_ep_disclosure
    ON endpoints(run_id, disclosure_worst);
