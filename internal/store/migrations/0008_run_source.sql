ALTER TABLE runs
    ADD COLUMN source text NOT NULL DEFAULT 'scan' CHECK (source IN ('scan', 'import', 'manual'));
