CREATE TABLE runs (
    id bigserial PRIMARY KEY,
    name text NOT NULL UNIQUE,
    inactive_after integer NOT NULL CHECK (inactive_after > 0),
    started_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz
);

CREATE TABLE run_groups (
    run_id bigint NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    group_index integer NOT NULL,
    completed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, group_index)
);

CREATE TABLE run_group_addresses (
    run_id bigint NOT NULL,
    group_index integer NOT NULL,
    address text NOT NULL,
    PRIMARY KEY (run_id, address),
    FOREIGN KEY (run_id, group_index) REFERENCES run_groups (run_id, group_index) ON DELETE CASCADE
);

CREATE INDEX run_group_addresses_address ON run_group_addresses (address, run_id);

CREATE TABLE hosts (
    id bigserial PRIMARY KEY,
    address text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    tags text[] NOT NULL DEFAULT '{}',
    notes bytea,
    display_name text NOT NULL DEFAULT '',
    owner text NOT NULL DEFAULT '',
    criticality text NOT NULL DEFAULT '',
    status_override text NOT NULL DEFAULT '',
    user_updated_at timestamptz
);

CREATE TABLE services (
    id bigserial PRIMARY KEY,
    host_id bigint NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    port integer NOT NULL CHECK (port BETWEEN 0 AND 65535),
    protocol text NOT NULL,
    UNIQUE (host_id, port, protocol)
);

CREATE TABLE host_observations (
    run_id bigint NOT NULL,
    group_index integer NOT NULL,
    host_id bigint NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    hostnames text[] NOT NULL DEFAULT '{}',
    observed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, host_id),
    FOREIGN KEY (run_id, group_index) REFERENCES run_groups (run_id, group_index) ON DELETE CASCADE
);

CREATE INDEX host_observations_host ON host_observations (host_id, run_id);

CREATE TABLE service_observations (
    id bigserial PRIMARY KEY,
    run_id bigint NOT NULL,
    group_index integer NOT NULL,
    service_id bigint NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    state text NOT NULL DEFAULT '',
    service text NOT NULL DEFAULT '',
    product text NOT NULL DEFAULT '',
    version text NOT NULL DEFAULT '',
    http jsonb,
    http_headers bytea,
    http_cookies bytea,
    observed_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (run_id, service_id),
    FOREIGN KEY (run_id, group_index) REFERENCES run_groups (run_id, group_index) ON DELETE CASCADE
);

CREATE INDEX service_observations_service ON service_observations (service_id, run_id);

CREATE TABLE technologies (
    id bigserial PRIMARY KEY,
    service_observation_id bigint NOT NULL REFERENCES service_observations (id) ON DELETE CASCADE,
    ordinal integer NOT NULL,
    name text NOT NULL,
    category text NOT NULL DEFAULT '',
    version text NOT NULL DEFAULT '',
    confidence integer NOT NULL DEFAULT 0,
    source text NOT NULL DEFAULT '',
    UNIQUE (service_observation_id, ordinal)
);

CREATE TABLE findings (
    id bigserial PRIMARY KEY,
    service_observation_id bigint NOT NULL REFERENCES service_observations (id) ON DELETE CASCADE,
    ordinal integer NOT NULL,
    signature_id text NOT NULL,
    kind text NOT NULL DEFAULT '',
    name text NOT NULL DEFAULT '',
    version text NOT NULL DEFAULT '',
    confidence integer NOT NULL DEFAULT 0,
    evidence bytea,
    UNIQUE (service_observation_id, ordinal)
);
