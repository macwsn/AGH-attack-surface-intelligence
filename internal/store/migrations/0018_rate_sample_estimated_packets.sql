ALTER TABLE run_rate_samples ADD COLUMN estimated_packets integer NOT NULL DEFAULT 0 CHECK (estimated_packets >= 0);
