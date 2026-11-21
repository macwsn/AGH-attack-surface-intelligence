CREATE TABLE signatures (
    id text PRIMARY KEY CHECK (id ~ '^[a-z0-9-]+$'),
    name text NOT NULL,
    kind text NOT NULL,
    source text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text NOT NULL DEFAULT ''
);
