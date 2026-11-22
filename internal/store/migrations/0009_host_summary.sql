CREATE TABLE host_summary (
    host_id bigint PRIMARY KEY REFERENCES hosts (id) ON DELETE CASCADE,
    address inet NOT NULL,
    last_run_id bigint NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    status text NOT NULL CHECK (status IN ('active', 'unstable', 'inactive')),
    missed_runs integer NOT NULL DEFAULT 0 CHECK (missed_runs >= 0),
    stability double precision NOT NULL DEFAULT 0,
    interest_score integer NOT NULL DEFAULT 0 CHECK (interest_score BETWEEN 0 AND 100),
    ports integer[] NOT NULL DEFAULT '{}',
    services text[] NOT NULL DEFAULT '{}',
    technologies text[] NOT NULL DEFAULT '{}',
    finding_kinds text[] NOT NULL DEFAULT '{}',
    titles text[] NOT NULL DEFAULT '{}',
    hostnames text[] NOT NULL DEFAULT '{}',
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL
);

CREATE INDEX host_summary_address ON host_summary (address);
CREATE INDEX host_summary_status ON host_summary (status, address);
CREATE INDEX host_summary_interest ON host_summary (interest_score, address);
CREATE INDEX host_summary_last_seen ON host_summary (last_seen, address);
CREATE INDEX host_summary_ports ON host_summary USING gin (ports);
CREATE INDEX host_summary_services ON host_summary USING gin (services);
CREATE INDEX host_summary_technologies ON host_summary USING gin (technologies);
CREATE INDEX host_summary_finding_kinds ON host_summary USING gin (finding_kinds);
CREATE INDEX hosts_tags ON hosts USING gin (tags);
