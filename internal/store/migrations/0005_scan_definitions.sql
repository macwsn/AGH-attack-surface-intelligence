CREATE TABLE scan_definitions (
    id bigserial PRIMARY KEY,
    name text NOT NULL UNIQUE CHECK (name <> ''),
    enabled boolean NOT NULL DEFAULT false,
    inactive_after integer NOT NULL CHECK (inactive_after > 0),
    settings jsonb NOT NULL,
    schedule jsonb NOT NULL,
    last_run_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE runs
    ADD COLUMN definition_id bigint REFERENCES scan_definitions (id) ON DELETE SET NULL,
    ADD COLUMN schedule jsonb,
    ADD COLUMN held boolean NOT NULL DEFAULT false,
    ADD COLUMN address_total integer CHECK (address_total >= 0);

CREATE UNIQUE INDEX runs_one_open_per_definition ON runs (definition_id) WHERE status IN ('running', 'paused');
