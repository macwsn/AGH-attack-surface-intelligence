ALTER TABLE host_observations ADD COLUMN notes text[] NOT NULL DEFAULT '{}';
