ALTER TABLE hosts
    ALTER COLUMN display_name DROP DEFAULT,
    ALTER COLUMN display_name DROP NOT NULL,
    ALTER COLUMN display_name TYPE bytea
        USING CASE WHEN display_name = '' THEN NULL ELSE '\x00'::bytea || convert_to(display_name, 'UTF8') END,
    ALTER COLUMN owner DROP DEFAULT,
    ALTER COLUMN owner DROP NOT NULL,
    ALTER COLUMN owner TYPE bytea
        USING CASE WHEN owner = '' THEN NULL ELSE '\x00'::bytea || convert_to(owner, 'UTF8') END;

ALTER TABLE scan_definitions ADD COLUMN scope bytea;
UPDATE scan_definitions SET scope = '\x00'::bytea || convert_to(jsonb_build_object(
        'targets', settings->'targets', 'excludes', settings->'excludes')::text, 'UTF8'),
    settings = settings - 'targets' - 'excludes';

ALTER TABLE runs
    ADD COLUMN scope bytea,
    ADD COLUMN definition_deleted boolean NOT NULL DEFAULT false;
UPDATE runs SET scope = '\x00'::bytea || convert_to(jsonb_build_object(
        'targets', settings->'targets', 'excludes', settings->'excludes')::text, 'UTF8'),
    settings = settings - 'targets' - 'excludes'
WHERE settings ? 'targets' OR settings ? 'excludes';

ALTER TABLE signatures ALTER COLUMN source TYPE bytea USING '\x00'::bytea || convert_to(source, 'UTF8');
ALTER TABLE hunts ALTER COLUMN source DROP NOT NULL;
ALTER TABLE hunts ALTER COLUMN source TYPE bytea
    USING CASE WHEN source = '' THEN NULL ELSE '\x00'::bytea || convert_to(source, 'UTF8') END;

DELETE FROM sessions;
ALTER TABLE sessions DROP COLUMN csrf_token, ADD COLUMN csrf_hash bytea NOT NULL;

DROP TRIGGER hosts_encryption_keys_insert ON hosts;
DROP TRIGGER hosts_encryption_keys_update ON hosts;
CREATE TRIGGER hosts_encryption_keys_insert AFTER INSERT ON hosts
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION track_encryption_keys('notes', 'display_name', 'owner');
CREATE TRIGGER hosts_encryption_keys_update AFTER UPDATE ON hosts
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION track_encryption_keys('notes', 'display_name', 'owner');
CREATE TRIGGER scan_definitions_encryption_keys_insert AFTER INSERT ON scan_definitions
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION track_encryption_keys('scope');
CREATE TRIGGER scan_definitions_encryption_keys_update AFTER UPDATE ON scan_definitions
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION track_encryption_keys('scope');
CREATE TRIGGER runs_encryption_keys_insert AFTER INSERT ON runs
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION track_encryption_keys('scope');
CREATE TRIGGER runs_encryption_keys_update AFTER UPDATE ON runs
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION track_encryption_keys('scope');
CREATE TRIGGER signatures_encryption_keys_insert AFTER INSERT ON signatures
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION track_encryption_keys('source');
CREATE TRIGGER signatures_encryption_keys_update AFTER UPDATE ON signatures
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION track_encryption_keys('source');
CREATE TRIGGER hunts_encryption_keys_insert AFTER INSERT ON hunts
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION track_encryption_keys('source');
CREATE TRIGGER hunts_encryption_keys_update AFTER UPDATE ON hunts
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION track_encryption_keys('source');
