# Holdout fixtures

Products the built-in signature pack was never written for, used to test the generic detection (wappalyzer
fingerprints, heuristics, generic admin-panel findings) in `internal/detect/generic_test.go`. Same format as
`testdata/pack/` (see its README); `source.txt` says where each one comes from.

- Captured (`source.txt` starts with `captured`): couchdb, gogs, influxdb, metabase, nacos, openfire, solr, webmin,
  from a first start of the local Vulhub image named there, with `curl -sS -i -L --max-redirs 5`, host rewritten to
  `fixture.test`. `openfire-console/` is the page Openfire's `/` sends a browser to with a meta refresh
  (`/index.jsp` -> `/login.jsp`); the scanner does not follow meta refreshes, so `openfire/` is what it sees on `/`.
- Written from documented markers (no image was available offline): airflow, nexus, superset. Replace them with
  captures (for example from `eval/vulhub/fixtures-holdout/`) when they are available.
