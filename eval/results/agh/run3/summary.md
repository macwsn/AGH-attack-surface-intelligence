# ASI vs the organisers' sample environments (lab-agh)
Commit `b4f6593`; target `host.docker.internal` (host ports published on 127.0.0.1; remaps: {}). Scenarios: A=PARTIAL B=PARTIAL C=PASS D=PASS E=PARTIAL F=PARTIAL G=PASS H=PARTIAL. Score: products 17/19, service names 20/20, versions 10/13, admin panels 5/5, outdated 2/2. Per-run durations and request counts: `summary.json` (`runs`).

| A Quickstart: PARTIAL (a1 11s/5 req, a2 10s/0 req, a3 11s/5 req, a-range 18s/5 req, a-top1000 17s/0 req) | Observed | Result |
|---|---|---|
| A1 scan 1 finds 2223, 3001, 5673, 8787, 15673 open; A2 diff a1->a2: exactly one change, service_missing on 8787; A3 diff a2->a3: exactly one change, service_returned on 8787; I1 quickstart scan of 5 explicit ports takes under 20 s (was 4…; A4 range list (8000-9000) finds the five quickstart ports | A1: open: [2223, 3001, 5673, 8787, 15673] (11 s); A2: service_missing 8787; A3: service_returned 8787; I1: a1 11 s, a2 10 s, a3 11 s; A4: found [2223, 3001, 5673, 8787, 15673], missed [], other open: [8021]; 18 s, exit 0 | PASS |
| A5 preset top1000 finds the five quickstart ports | found [3001], missed [2223, 5673, 8787, 15673], other open: [8021]; 17 s, exit 0 | PARTIAL |

| B custom-network: PARTIAL (b1 19s/5 req) | Observed | Result |
|---|---|---|
| B1 all 7 ports found open; B2a service name right on every port; B2c admin interfaces flagged (finding kind admin-panel): 15673; B3 CSV export: one row per service with the contract columns | B1: open: [2223, 3001, 5673, 8787, 8888, 15432, 15673] (19 s); B2a: 7/7; wrong: -; B2c: flagged 1/1; missing: -; B3: 7 rows, missing columns: none | PASS |
| B2b product/application recognised on every port | 6/7; not recognised: 5673 (RabbitMQ 3.x AMQP; got 'Advanced Message Queue Protocol') | PARTIAL |

| C modern: PASS (c1 15s/13 req) | Observed | Result |
|---|---|---|
| C1 ports 80, 81, 443, 6379, 8080, 8081 found open; C2a service name right on every port; C2b product/application recognised on every port; C2c admin interfaces flagged (finding kind admin-panel): 8081, …; C3 8080: redirect to the WordPress installer is followed and r…; C4 443 speaks TLS but rejects the handshake without a configur…; C5 cookies and notable headers collected (phpMyAdmin cookie, X…; C6 notable headers/… | C1: open: [80, 81, 443, 6379, 8080, 8081] (15 s); C2a: 6/6; wrong: -; C2b: 5/5; not recognised: -; C2c: flagged 2/2; missing: -; C3: status 200, title 'WordPress › Installation', redirect_chain ['http://host.docker.internal:8080/wp-admin/inst…; C4: service=http product='openresty' http={"scheme": "https", "url": "https://host.docker.internal/", "status_cod…; C5: cookies {"80": [], "81": [], "443": [], "8080": [], "8081": ["phpMyAdmin", "phpMyAdmin", "pma_lang", "phpMyAd…; C6: 5 such findings on 6 services | PASS |

| D modern-proxy (Toxiproxy): PASS (d1 9s/8 req, d1b 9s/8 req, d2 13s/9 req, d3 11s/5 req) | Observed | Result |
|---|---|---|
| D1 export has a response time field for 8085; D9 two scans of the unchanged Traefik stack give an empty diff; D2 with 500 ms latency the recorded response time is >= 500 ms; D3 diff no-latency -> latency reports no change (only slower); D4 with the timeout toxic (1000 ms) the scan still completes; D5 8085 is still recorded as an open service when its backend …; D6 diff no-latency -> timeout: no false change (nothing… | D1: no latency: {'ttfb_ms': 8, 'response_time_ms': 765}; D9: no changes; D2: latency run: {'ttfb_ms': 515, 'response_time_ms': 1793} (baseline {'ttfb_ms': 8, 'response_time_ms': 765}); s…; D3: no changes; D4: exit 0 after 11 s (baseline 9 s); D5: 8085: state=open status=active; http-proxy -; HTTP 502 '' server=-; tech: -; findings: -; D6: service_changed 8085 [findings,http.favicon_sha256,http.headers.cache-control,http.headers.content-type,http.…; D8: scheme per run: {"d1": {"8085": "http", "8086": "http", "8474": "http"}, "d2": {"8085": "http", "8086": "http…; D7a: 3/3; wrong: -; D7b: 3/3; not recognised: -; D7c: flagged 1/1; missing: - | PASS |

| E vulnerable: PARTIAL (e1 15s/19 req) | Observed | Result |
|---|---|---|
| E1 21, 8088, 8089, 8090 found open (passive range 21000-21010 …; E2a service name right on every port; E2c admin interfaces flagged (finding kind admin-panel): 8089; E3 8088: WordPress version 4.7.x detected; E4 outdated finding for WordPress 4.7 on 8088; E5 outdated finding for the old PHP on 8088; E7 strictly non-intrusive: web access logs show only GET/HEAD … | E1: open: [21, 8088, 8089, 8090, 21000, 21001, 21002, 21003, 21004, 21005, 21006, 21007, 21008, 21009, 21010] (15…; E2a: 4/4; wrong: -; E2c: flagged 1/1; missing: -; E3: http Apache httpd 2.4.10; HTTP 200 'WordPress › Installation' server=Apache/2.4.10 (Debian); tech: WordPress …; E4: outdated findings: {"8088": ["Outdated WordPress 4.7.5 (WordPress 4.7.5 is older than the minimum supported v…; E5: x-powered-by on 8088: 'PHP/5.6.30'; outdated findings on 8088: ['Outdated WordPress 4.7.5 (WordPress 4.7.5 is…; E7: methods ['GET']; adminer: 5 requests, paths ['/', '/api/version', '/favicon.ico', '/version']; dvwa: 6 reques… | PASS |
| E2b product/application recognised on every port | 3/4; not recognised: 21 (FTP vsftpd; got '') | PARTIAL |

| F custom signature: PARTIAL (f0 11s/5 req, f1 12s/5 req) | Observed | Result |
|---|---|---|
| F1 without the signature file: RabbitMQ UI / Gitea produce no …; F2 with --signatures-dir: the 3 custom findings appear (admin-…; F4 diff before/after reports only findings/technologies change…; F5 a signature using POST is rejected with an error naming the… | F1: 15673: http Cowboy httpd; HTTP 200 'RabbitMQ Management' server=Cowboy; tech: RabbitMQ; findings: builtin-rab…; F2: findings: [(3001, 'agh-gitea', 'technology'), (3001, 'agh-gitea-cookie', 'interesting-cookie'), (15673, 'agh-…; F4: service_changed 3001 [findings]; service_changed 15673 [findings]; F5: asi scan: --signatures-dir: /work/badsig/bad.yaml: signature "agh-bad-post" violates rule "methods GET and HE… | PASS |
| F3 technology signature also yields a technologies entry with source signature:<id> | no such technologies entry on 3001 | FAIL |

| G import/export: PASS (no scan) | Observed | Result |
|---|---|---|
| G1 JSON export imports into a fresh database; G2 re-export equals the source: hosts, services, products, ver…; G3 HTTP details (headers, cookie names, TLS) survive the round…; G4 CSV export imports into a fresh database with the same serv… | G1: imported 1 hosts, 7 services as run import-20261121T220755.725092Z; 0 invalid rows; 1 changes; 0 left as stor…; G2: 1 hosts/7 services -> 1 hosts/7 services; differences: none; G3: differences: none; G4: imported 1 hosts, 7 services as run import-20261121T220756.400235Z; 0 invalid rows; 1 changes; 0 left as stor… | PASS |

| H recheck mode: PARTIAL (h1 20s/5 req, h2 20s/5 req, h3 19s/0 req) | Observed | Result |
|---|---|---|
| H1 recheck after a full scan completes and covers the same ser…; H2 diff full -> recheck is empty; H4 8787 stopped, recheck again: exactly service_missing 8787 | H1: full h1 20 s (5 requests in target logs) vs recheck h2 20 s (5 requests: {"flask-app": 5}), exit 0; open afte…; H2: no changes; H4: service_missing 8787; recheck h3 19 s, exit 0 | PASS |
| H3 recheck is faster than the full scan | 20 s vs 20 s | PARTIAL |
## Defects
1. **Applications are not recognised as product/technology even when the title names them; versions missing (WordPress 4.7)** (checks B2b, E2b). Expected: product/application recognised on every port. Happened: B2b: 6/7; not recognised: 5673 (RabbitMQ 3.x AMQP; got 'Advanced Message Queue Protocol'); E2b: 3/4; not recognised: 21 (FTP vsftpd; got ''). Command: `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports 2223,3001,5673,8787,8888,15432,15673 --name b1 --max-rate 300  --wait`. Output: `6/7; not recognised: 5673 (RabbitMQ 3.x AMQP; got 'Advanced Message Queue Protocol')`
2. **Preset top1000 does not contain most of the organisers' ports** (checks A5). Expected: preset top1000 finds the five quickstart ports. Happened: A5: found [3001], missed [2223, 5673, 8787, 15673], other open: [8021]; 17 s, exit 0. Command: `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports top1000 --name a-top1000 --max-rate 300  --wait`. Output: ` run a-top1000 status=completed started=2026-11-21T22:02:59Z finished=2026-11-21T22:03:16Z mode=full packets=2007 max_rate=300 adaptive=true actual_peak=40.9/s actual_avg=21.2/s actual_chart=▁▂ limit_chart=██ groups=1 addresses=1…`
3. **technology signature also yields a technologies entry with source signature:<id>** (checks F3). Expected: technology signature also yields a technologies entry with source signature:<id>. Happened: F3: no such technologies entry on 3001. Command: `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports 2223,3001,5673,8787,15673 --name f1 --max-rate 300 --signatures-dir /work/signatures --wait`. Output: `no such technologies entry on 3001`
4. **recheck is faster than the full scan** (checks H3). Expected: recheck is faster than the full scan. Happened: H3: 20 s vs 20 s. Command: `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports 2223,3001,5673,8787,8888,15432,15673 --name h2 --max-rate 300 --mode recheck --wait`. Output: `20 s vs 20 s`
## Recognition table (svc/prod/ver/admin/outdated: Y, N, - = not applicable)
| Port | Truth | ASI: service / product version | Technologies | Findings | svc/prod/ver/admin/outdated |
|---|---|---|---|---|---|
| 8888 | httpbin 0.9.2 (HTTP, gunicorn 19.9) | http / -  | httpbin 0.9.2 | builtin-httpbin[technology], builtin-header-server[interesting-header] | Y/Y/Y/-/- |
| 15432 | PostgreSQL 16 | postgresql / PostgreSQL DB 9.6.0 or later | PostgreSQL 9.6.0 | - | Y/Y/N/-/- |
| 5673 | RabbitMQ 3.x AMQP | amqp / Advanced Message Queue Protocol  | - | - | Y/N/N/-/- |
| 15673 | RabbitMQ management UI (admin) | http / Cowboy httpd  | RabbitMQ  | builtin-rabbitmq-management[technology], builtin-rabbitmq-management-ui[admin-p… | Y/Y/-/Y/- |
| 3001 | Gitea (web) | http / Golang net/http server  | Gitea 28.4.0 | builtin-gitea[technology], builtin-login-form[admin-panel] | Y/Y/-/-/- |
| 2223 | Gitea SSH (OpenSSH) | ssh / OpenSSH 10.3 | OpenSSH 10.3 | - | Y/Y/Y/-/- |
| 8787 | nginx | http / nginx 1.31.9 | nginx 1.31.9 | builtin-header-server[interesting-header] | Y/Y/Y/-/- |
| 8080 | WordPress (fresh, installer redirect) | http / Apache httpd 2.4.71 | WordPress 7.1.5, Apache 2.4.71, PHP 8.3.37 | builtin-wordpress-install[technology], builtin-header-x-powered-by[interesting-… | Y/Y/Y/-/- |
| 8081 | phpMyAdmin (admin) | http / Apache httpd 2.4.71 | phpMyAdmin 5.2.3, Apache 2.4.71, PHP 8.3.37 | builtin-phpmyadmin[technology], builtin-phpmyadmin-login[admin-panel], builtin-… | Y/Y/Y/Y/- |
| 6379 | Redis 7 | redis / Redis key-value store 7.4.12 | Redis 7.4.12 | - | Y/Y/Y/-/- |
| 80 | Nginx Proxy Manager default site (openresty) | http / OpenResty web app server  | - | - | Y/Y/-/-/- |
| 81 | Nginx Proxy Manager admin UI (admin) | http / OpenResty web app server  | Nginx Proxy Manager  | builtin-nginx-proxy-manager[technology], builtin-nginx-proxy-manager-ui[admin-p… | Y/Y/-/Y/- |
| 443 | Nginx Proxy Manager TLS (rejects handshake w… | http / openresty  | - | - | Y/-/-/-/- |
| 8085 | WordPress behind Traefik+Toxiproxy | http / Apache httpd 2.4.71 | WordPress 7.1.5, Apache 2.4.71, PHP 8.3.37 | builtin-wordpress-install[technology], builtin-header-x-powered-by[interesting-… | Y/Y/-/-/- |
| 8086 | Traefik 3.1 dashboard (admin) | http / Golang net/http server  | Traefik 3.1.7 | builtin-traefik-dashboard[technology], builtin-traefik-dashboard-ui[admin-panel… | Y/Y/Y/Y/- |
| 8474 | Toxiproxy 2.12 API | http / Golang net/http server  | Toxiproxy 2.12.0 | builtin-toxiproxy[technology] | Y/Y/Y/-/- |
| 21 | FTP vsftpd | ftp / -  | - | - | Y/N/N/-/- |
| 8088 | WordPress 4.7 on old PHP (outdated) | http / Apache httpd 2.4.10 | WordPress 4.7.5, Apache 2.4.10, PHP 5.6.30 | builtin-wordpress-install[technology], builtin-header-x-powered-by[interesting-… | Y/Y/Y/-/2/2 |
| 8089 | Adminer (admin) | http / -  | Adminer 6.3.0, PHP 8.4.28 | builtin-adminer[technology], builtin-adminer-login[admin-panel], builtin-header… | Y/Y/Y/Y/- |
| 8090 | DVWA | http / Apache httpd 2.4.25 | DVWA 1.10, Apache 2.4.25, PHP  | builtin-dvwa[technology], builtin-header-server[interesting-header], builtin-co… | Y/Y/-/-/- |
