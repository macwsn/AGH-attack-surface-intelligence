ALTER TABLE runs ADD COLUMN packets bigint NOT NULL DEFAULT 0 CHECK (packets >= 0);

ALTER TABLE run_group_addresses ADD COLUMN ports integer[];

CREATE INDEX runs_completed_definition ON runs (definition_id, id) WHERE status = 'completed';
