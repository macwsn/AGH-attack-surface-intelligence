CREATE TABLE builtin_signatures (
    id text PRIMARY KEY CHECK (id ~ '^builtin-[a-z0-9-]+$'),
    enabled boolean NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text NOT NULL DEFAULT ''
);
