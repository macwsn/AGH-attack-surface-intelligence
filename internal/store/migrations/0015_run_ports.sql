CREATE FUNCTION run_settings_ports(settings jsonb) RETURNS integer[] LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN jsonb_typeof(settings->'ports') = 'array' AND jsonb_array_length(settings->'ports') > 0
        THEN ARRAY(SELECT jsonb_array_elements_text(settings->'ports')::integer) END
$$;

ALTER TABLE runs ADD COLUMN ports integer[] GENERATED ALWAYS AS (run_settings_ports(settings)) STORED;
