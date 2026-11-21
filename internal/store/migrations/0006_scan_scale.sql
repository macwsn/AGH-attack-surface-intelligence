ALTER TABLE runs ADD COLUMN IF NOT EXISTS address_total integer CHECK (address_total >= 0);

CREATE TABLE run_failed_groups (
    run_id bigint NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    group_index integer NOT NULL,
    addresses text[] NOT NULL,
    reason text NOT NULL DEFAULT '',
    failed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, group_index)
);
