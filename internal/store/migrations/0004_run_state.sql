ALTER TABLE runs
    ADD COLUMN status text NOT NULL DEFAULT 'completed'
        CHECK (status IN ('running', 'paused', 'completed', 'failed')),
    ADD COLUMN settings jsonb NOT NULL DEFAULT '{}';

ALTER TABLE runs ALTER COLUMN status SET DEFAULT 'running';

ALTER TABLE run_groups
    ADD COLUMN address_count integer NOT NULL DEFAULT 0 CHECK (address_count >= 0),
    ADD COLUMN hosts_found integer NOT NULL DEFAULT 0 CHECK (hosts_found >= 0),
    ADD COLUMN duration_ns bigint NOT NULL DEFAULT 0 CHECK (duration_ns >= 0);
