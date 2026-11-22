# ASI vs the organisers' sample environments (lab-agh)
Commit `49e0f42`; target `host.docker.internal` (host ports published on 127.0.0.1; remaps: {}). Scenarios: A=PASS B=PARTIAL C=PARTIAL D=PARTIAL E=PARTIAL. Score: products 14/19, service names 18/20, versions 8/13, admin panels 4/5, outdated 2/2. Per-run durations and request counts: `summary.json` (`runs`).

| A Quickstart: PASS (a1 48s/5 req, a2 48s/0 req, a3 48s/5 req) | Observed | Result |
|---|---|---|
| A1 scan 1 finds 2223, 3001, 5673, 8787, 15673 open; A2 diff a1->a2: exactly one change, service_missing on 8787; A3 diff a2->a3: exactly one change, service_returned on 8787 | A1: open: [2223, 3001, 5673, 8787, 15673] (48 s); A2: service_missing 8787; A3: service_returned 8787 | PASS |

| B custom-network: PARTIAL (b1 48s/5 req) | Observed | Result |
|---|---|---|
| B1 all 7 ports found open; B2c admin interfaces flagged (finding kind admin-panel): 15673; B3 CSV export: one row per service with the contract columns | B1: open: [2223, 3001, 5673, 8787, 8888, 15432, 15673] (48 s); B2c: flagged 1/1; missing: -; B3: 7 rows, missing columns: none | PASS |
| B2a service name right on every port | 5/7; wrong: 8888=tcpwrapped, 15432=none | PARTIAL |
| B2b product/application recognised on every port | 4/7; not recognised: 8888 (httpbin; got ''), 15432 (PostgreSQL 16; got ''), 5673 (RabbitMQ 3.x AMQP; got 'Advanced Message Queue Protocol') | PARTIAL |

| C modern: PARTIAL (c1 9s/13 req) | Observed | Result |
|---|---|---|
| C1 ports 80, 81, 443, 6379, 8080, 8081 found open; C2a service name right on every port; C2b product/application recognised on every port; C2c admin interfaces flagged (finding kind admin-panel): 8081, …; C3 8080: redirect to the WordPress installer is followed and r…; C4 443 speaks TLS but rejects the handshake without a configur…; C5 cookies and notable headers collected (phpMyAdmin cookie, X… | C1: open: [80, 81, 443, 6379, 8080, 8081] (9 s); C2a: 6/6; wrong: -; C2b: 5/5; not recognised: -; C2c: flagged 2/2; missing: -; C3: status 200, title 'WordPress › Installation', redirect_chain ['http://host.docker.internal:8080/wp-admin/inst…; C4: service=https product='' http=null (contract: `service` stays `http`, `http.scheme` = https); C5: cookies {"80": [], "81": [], "8080": [], "8081": ["phpMyAdmin", "phpMyAdmin", "pma_lang", "phpMyAdmin"]}; hea… | PASS |
| C6 notable headers/cookies are flagged as findings (kind interesting-header / interesting-cookie), e.g. X-Powere… | 0 such findings on 6 services | FAIL |

| D modern-proxy (Toxiproxy): PARTIAL (d1 15s/7 req, d2 18s/9 req) | Observed | Result |
|---|---|---|
| D1 export has a response time field for 8085; D2 with 500 ms latency the recorded response time is >= 500 ms; D7a service name right on every port | D1: no latency: {'ttfb_ms': 15, 'response_time_ms': 810}; D2: latency run: {'ttfb_ms': 513, 'response_time_ms': 1829} (baseline {'ttfb_ms': 15, 'response_time_ms': 810}); …; D7a: 3/3; wrong: - | PASS |
| D3 diff no-latency -> latency reports no change (only slower) | service_changed 8086 [http.tls.sha256] | FAIL |
| D8 plain-HTTP ports 8085/8086/8474 are fetched over http in every run (8086 = 301 to /dashboard/, title 'Traefik… | scheme per run: {"d1": {"8085": "http", "8086": "https", "8474": "http"}, "d2": {"8085": "http", "8086": "https", "8474": "http"}}; 8086 in d1: https://host.docker.internal:8086/ status 404 title '' tls.subject_cn 'TRAEFIK DEFAULT CERT' | FAIL |
| D7b product/application recognised on every port | 2/3; not recognised: 8086 (Traefik 3.1 dashboard; got 'Golang net/http server') | PARTIAL |
| D7c admin interfaces flagged (finding kind admin-panel): 8086 | flagged 0/1; missing: 8086 findings=[] | FAIL |

| E vulnerable: PARTIAL (e1 22s/22 req) | Observed | Result |
|---|---|---|
| E1 21, 8088, 8089, 8090 found open (passive range 21000-21010 …; E2a service name right on every port; E2c admin interfaces flagged (finding kind admin-panel): 8089; E3 8088: WordPress version 4.7.x detected; E4 outdated finding for WordPress 4.7 on 8088; E5 outdated finding for the old PHP on 8088 | E1: open: [21, 8088, 8089, 8090, 21000, 21001, 21002, 21003, 21004, 21005, 21006, 21007, 21008, 21009, 21010] (22…; E2a: 4/4; wrong: -; E2c: flagged 1/1; missing: -; E3: http Apache httpd 2.4.10; HTTP 200 'WordPress › Installation' server=Apache/2.4.10 (Debian); tech: WordPress …; E4: outdated findings: {"8088": ["Outdated WordPress 4.7.5 (WordPress 4.7.5 is older than the minimum supported 6…; E5: x-powered-by on 8088: 'PHP/5.6.30'; outdated findings on 8088: ['Outdated WordPress 4.7.5 (WordPress 4.7.5 is… | PASS |
| E2b product/application recognised on every port | 3/4; not recognised: 21 (FTP vsftpd; got '') | PARTIAL |
| E7 strictly non-intrusive: web access logs show only GET/HEAD from the scanner | methods ['GET', 'OPTIONS']; adminer: 8 requests, paths ['/', '/?CAVIT', '/api/version', '/favicon.ico', '/nice%20ports%2C/Tri%6Eity.txt%2ebak', '/version']; dvwa: 6 requests, paths ['/', '/api/version', '/favicon.ico', '/login.php', '/version']; wordpress: 8 … | FAIL |
## Defects
1. **No built-in findings: admin panels, outdated versions and notable headers/cookies are never flagged (only custom signatures produce findings)** (checks C6, D7c). Expected: notable headers/cookies are flagged as findings (kind interesting-header / interesting-cookie), e.g. X-Powere…. Happened: C6: 0 such findings on 6 services; D7c: flagged 0/1; missing: 8086 findings=[]. Command: `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports 80,81,443,6379,8080,8081 --name c1 --max-rate 300  --wait`. Output: `0 such findings on 6 services`
2. **Applications are not recognised as product/technology even when the title names them; versions missing (WordPress 4.7)** (checks B2b, D7b, E2b). Expected: product/application recognised on every port. Happened: B2b: 4/7; not recognised: 8888 (httpbin; got ''), 15432 (PostgreSQL 16; got ''), 5673 (RabbitMQ 3.x AMQP; got 'Advanced Message Queue Protocol'); D7b: 2/3; not recognised: 8086 (Traefik 3.1 dashboard; got 'Golang net/http server'); E2b: 3/4; not recognised: 21 (FTP vsftpd; got ''). Command: `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports 2223,3001,5673,8787,8888,15432,15673 --name b1 --max-rate 300  --wait`. Output: `4/7; not recognised: 8888 (httpbin; got ''), 15432 (PostgreSQL 16; got ''), 5673 (RabbitMQ 3.x AMQP; got 'Advanced Message Queue Protocol')`
3. **Service not identified: nmap runs with `--version-light` (PostgreSQL empty; plain `nmap -sV` says postgresql) and a port nmap calls tcpwrapped gets no HTTP probe (httpbin)** (checks B2a). Expected: service name right on every port. Happened: B2a: 5/7; wrong: 8888=tcpwrapped, 15432=none. Command: `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports 2223,3001,5673,8787,8888,15432,15673 --name b1 --max-rate 300  --wait`. Output: `{"port": 8888, "service": "tcpwrapped", "product": "", "http": null}; {"port": 15432, "service": "", "product": "", "http": null}`
4. **Ports that answer both TLS and plain HTTP (Traefik) are recorded over https: wrong content (404 instead of the dashboard) and false changes because the default cert changes on restart** (checks D8, D3). Expected: plain-HTTP ports 8085/8086/8474 are fetched over http in every run (8086 = 301 to /dashboard/, title 'Traefik…. Happened: D8: scheme per run: {"d1": {"8085": "http", "8086": "https", "8474": "http"}, "d2": {"8085": "http", "8086": "https", "8474": "http"}}; 8086 in d1: https…; D3: service_changed 8086 [http.tls.sha256]. Command: `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports 8085,8086,8474 --name d1 --max-rate 300  --wait`. Output: `$ curl -si http://127.0.0.1:8086/ / head -2 HTTP/1.1 301 Moved Permanently Location: http://127.0.0.1:8086/dashboard/ $ curl -s http://127.0.0.1:8086/dashboard/ / grep -o '<title>.*</title>' <title>Traefik</title> $ curl -ski htt…`
5. **Not strictly GET/HEAD: nmap service detection sends OPTIONS and non-HTTP probes to ports it cannot identify** (checks E7). Expected: strictly non-intrusive: web access logs show only GET/HEAD from the scanner. Happened: E7: methods ['GET', 'OPTIONS']; adminer: 8 requests, paths ['/', '/?CAVIT', '/api/version', '/favicon.ico', '/nice%20ports%2C/Tri%6Eity.txt%2ebak', '/ver…. Command: `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports 21,8088,8089,8090,21000-21010 --name e1 --max-rate 300  --wait`. Output: `[Sat Nov 21 19:56:02 2026] [::ffff:172.21.0.1]:59902 [200]: OPTIONS /`
## Recognition table (svc/prod/ver/admin/outdated: Y, N, - = not applicable)
| Port | Truth | ASI: service / product version | Technologies | Findings | svc/prod/ver/admin/outdated |
|---|---|---|---|---|---|
| 8888 | httpbin (HTTP, gunicorn 19.9) | tcpwrapped / -  | - | - | N/N/N/-/- |
| 15432 | PostgreSQL 16 | none / -  | - | - | N/N/N/-/- |
| 5673 | RabbitMQ 3.x AMQP | amqp / Advanced Message Queue Protocol  | - | - | Y/N/N/-/- |
| 15673 | RabbitMQ management UI (admin) | http / Cowboy httpd  | RabbitMQ  | builtin-rabbitmq-management[technology], builtin-rabbitmq-management-ui[admin-p… | Y/Y/-/Y/- |
| 3001 | Gitea (web) | http / Golang net/http server  | Gitea 28.4.0 | builtin-gitea[technology] | Y/Y/-/-/- |
| 2223 | Gitea SSH (OpenSSH) | ssh / OpenSSH 10.3 | OpenSSH 10.3 | - | Y/Y/Y/-/- |
| 8787 | nginx | http / nginx 1.31.9 | nginx 1.31.9 | - | Y/Y/Y/-/- |
| 8080 | WordPress (fresh, installer redirect) | http / Apache httpd 2.4.71 | WordPress 7.1.5, Apache 2.4.71, PHP 8.3.37 | builtin-wordpress-install[technology] | Y/Y/Y/-/- |
| 8081 | phpMyAdmin (admin) | http / Apache httpd 2.4.71 | phpMyAdmin 5.2.3, Apache 2.4.71, PHP 8.3.37 | builtin-phpmyadmin[technology], builtin-phpmyadmin-login[admin-panel] | Y/Y/Y/Y/- |
| 6379 | Redis 7 | redis / Redis key-value store 7.4.12 | Redis 7.4.12 | - | Y/Y/Y/-/- |
| 80 | Nginx Proxy Manager default site (openresty) | http / OpenResty web app server  | - | - | Y/Y/-/-/- |
| 81 | Nginx Proxy Manager admin UI (admin) | http / OpenResty web app server  | Nginx Proxy Manager  | builtin-nginx-proxy-manager[technology], builtin-nginx-proxy-manager-ui[admin-p… | Y/Y/-/Y/- |
| 443 | Nginx Proxy Manager TLS (rejects handshake w… | https / -  | - | - | Y/-/-/-/- |
| 8085 | WordPress behind Traefik+Toxiproxy | http / Apache httpd 2.4.71 | WordPress 7.1.5, Apache 2.4.71, PHP 8.3.37 | builtin-wordpress-install[technology] | Y/Y/-/-/- |
| 8086 | Traefik 3.1 dashboard (admin) | http / Golang net/http server  | - | - | Y/N/N/N/- |
| 8474 | Toxiproxy 2.12 API | http / Golang net/http server  | Toxiproxy 2.12.0 | builtin-toxiproxy[technology] | Y/Y/Y/-/- |
| 21 | FTP vsftpd | ftp / -  | - | - | Y/N/N/-/- |
| 8088 | WordPress 4.7 on old PHP (outdated) | http / Apache httpd 2.4.10 | WordPress 4.7.5, Apache 2.4.10, PHP 5.6.30 | builtin-wordpress-install[technology], outdated-wordpress[outdated], outdated-a… | Y/Y/Y/-/2/2 |
| 8089 | Adminer (admin) | http / -  | Adminer 6.3.0, PHP 8.4.28 | builtin-adminer[technology], builtin-adminer-login[admin-panel] | Y/Y/Y/Y/- |
| 8090 | DVWA | http / Apache httpd 2.4.25 | DVWA 1.10, Apache 2.4.25, PHP  | builtin-dvwa[technology], outdated-apache[outdated] | Y/Y/-/-/- |
