CREATE INDEX service_observations_with_body ON service_observations (service_id, run_id) WHERE http_body IS NOT NULL;
