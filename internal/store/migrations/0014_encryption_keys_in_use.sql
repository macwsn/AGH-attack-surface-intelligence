CREATE TABLE encryption_keys_in_use (
    table_name text NOT NULL,
    column_name text NOT NULL,
    key_header text NOT NULL,
    PRIMARY KEY (table_name, column_name, key_header)
);

CREATE FUNCTION track_encryption_keys() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    c text;
BEGIN
    FOREACH c IN ARRAY TG_ARGV LOOP
        EXECUTE format('INSERT INTO encryption_keys_in_use (table_name, column_name, key_header)
            SELECT DISTINCT %L, %L, encode(substring(%I from 1 for 9), ''hex'') FROM new_rows WHERE %I IS NOT NULL
            ON CONFLICT DO NOTHING', TG_TABLE_NAME, c, c, c);
    END LOOP;
    RETURN NULL;
END
$$;

CREATE TRIGGER settings_encryption_keys_insert AFTER INSERT ON settings
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION track_encryption_keys('value');
CREATE TRIGGER settings_encryption_keys_update AFTER UPDATE ON settings
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION track_encryption_keys('value');
CREATE TRIGGER hosts_encryption_keys_insert AFTER INSERT ON hosts
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION track_encryption_keys('notes');
CREATE TRIGGER hosts_encryption_keys_update AFTER UPDATE ON hosts
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION track_encryption_keys('notes');
CREATE TRIGGER service_observations_encryption_keys_insert AFTER INSERT ON service_observations
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT
    EXECUTE FUNCTION track_encryption_keys('http_headers', 'http_cookies', 'http_body');
CREATE TRIGGER service_observations_encryption_keys_update AFTER UPDATE ON service_observations
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT
    EXECUTE FUNCTION track_encryption_keys('http_headers', 'http_cookies', 'http_body');
CREATE TRIGGER findings_encryption_keys_insert AFTER INSERT ON findings
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION track_encryption_keys('evidence');
CREATE TRIGGER findings_encryption_keys_update AFTER UPDATE ON findings
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION track_encryption_keys('evidence');
CREATE TRIGGER hunt_results_encryption_keys_insert AFTER INSERT ON hunt_results
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION track_encryption_keys('evidence');
CREATE TRIGGER hunt_results_encryption_keys_update AFTER UPDATE ON hunt_results
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION track_encryption_keys('evidence');

INSERT INTO encryption_keys_in_use (table_name, column_name, key_header)
SELECT DISTINCT 'settings', 'value', encode(substring(value from 1 for 9), 'hex') FROM settings WHERE value IS NOT NULL
UNION SELECT DISTINCT 'hosts', 'notes', encode(substring(notes from 1 for 9), 'hex') FROM hosts WHERE notes IS NOT NULL
UNION SELECT DISTINCT 'service_observations', 'http_headers', encode(substring(http_headers from 1 for 9), 'hex')
    FROM service_observations WHERE http_headers IS NOT NULL
UNION SELECT DISTINCT 'service_observations', 'http_cookies', encode(substring(http_cookies from 1 for 9), 'hex')
    FROM service_observations WHERE http_cookies IS NOT NULL
UNION SELECT DISTINCT 'service_observations', 'http_body', encode(substring(http_body from 1 for 9), 'hex')
    FROM service_observations WHERE http_body IS NOT NULL
UNION SELECT DISTINCT 'findings', 'evidence', encode(substring(evidence from 1 for 9), 'hex') FROM findings WHERE evidence IS NOT NULL
UNION SELECT DISTINCT 'hunt_results', 'evidence', encode(substring(evidence from 1 for 9), 'hex') FROM hunt_results WHERE evidence IS NOT NULL;
