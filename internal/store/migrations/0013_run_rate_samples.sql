CREATE TABLE run_rate_samples (
    run_id bigint NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    minute timestamptz NOT NULL,
    configured_limit integer NOT NULL CHECK (configured_limit >= 0),
    effective_limit integer NOT NULL CHECK (effective_limit >= 0),
    sent integer NOT NULL DEFAULT 0 CHECK (sent >= 0),
    PRIMARY KEY (run_id, minute)
);
