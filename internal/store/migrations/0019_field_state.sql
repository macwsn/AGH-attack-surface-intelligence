ALTER TABLE service_observations ADD COLUMN field_state bytea;

DROP TRIGGER service_observations_encryption_keys_insert ON service_observations;
DROP TRIGGER service_observations_encryption_keys_update ON service_observations;
CREATE TRIGGER service_observations_encryption_keys_insert AFTER INSERT ON service_observations
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT
    EXECUTE FUNCTION track_encryption_keys('http_headers', 'http_cookies', 'http_body', 'field_state');
CREATE TRIGGER service_observations_encryption_keys_update AFTER UPDATE ON service_observations
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT
    EXECUTE FUNCTION track_encryption_keys('http_headers', 'http_cookies', 'http_body', 'field_state');
