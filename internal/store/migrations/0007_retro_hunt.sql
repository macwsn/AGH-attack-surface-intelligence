ALTER TABLE service_observations ADD COLUMN http_body bytea;

ALTER TABLE findings ADD COLUMN source text NOT NULL DEFAULT '';

CREATE TABLE hunts (
    id bigserial PRIMARY KEY,
    signature_id text NOT NULL,
    source text NOT NULL,
    actor text NOT NULL,
    since timestamptz,
    latest_run_id bigint REFERENCES runs (id) ON DELETE SET NULL,
    observations integer NOT NULL DEFAULT 0,
    matched integer NOT NULL DEFAULT 0,
    in_latest integer NOT NULL DEFAULT 0,
    not_evaluable integer NOT NULL DEFAULT 0,
    duration_ns bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE hunt_results (
    hunt_id bigint NOT NULL REFERENCES hunts (id) ON DELETE CASCADE,
    service_id bigint NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    address text NOT NULL,
    port integer NOT NULL,
    protocol text NOT NULL,
    evaluable boolean NOT NULL,
    first_run_id bigint REFERENCES runs (id) ON DELETE SET NULL,
    last_run_id bigint REFERENCES runs (id) ON DELETE SET NULL,
    in_latest boolean NOT NULL DEFAULT false,
    version text NOT NULL DEFAULT '',
    evidence bytea,
    PRIMARY KEY (hunt_id, service_id)
);
