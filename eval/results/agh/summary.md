# ASI vs the organisers' sample environments (lab-agh)
Commit `efeab4e`; target `host.docker.internal` (host ports published on 127.0.0.1; remaps: {}). Scenarios: A=PARTIAL B=PARTIAL C=PARTIAL D=PARTIAL E=PARTIAL F=PASS G=PASS. Score: products 7/19, service names 18/20, versions 3/13, admin panels 0/5, outdated 0/2. Per-run durations and request counts: `summary.json` (`runs`).

| A Quickstart: PARTIAL (a1 48s/3 req, a2 48s/0 req, a3 48s/3 req, a-range 55s/3 req, a-top1000 55s/0 req) | Observed | Result |
|---|---|---|
| A1 scan 1 finds 2223, 3001, 5673, 8787, 15673 open; A2 diff a1->a2: exactly one change, service_missing on 8787; A3 diff a2->a3: exactly one change, service_returned on 8787; A4 range list (8000-9000) finds the five quickstart ports | A1: open: [2223, 3001, 5673, 8787, 15673] (48 s); A2: service_missing 8787; A3: service_returned 8787; A4: found [2223, 3001, 5673, 8787, 15673], missed [], other open: [8021, 8080]; 55 s, exit 0 | PASS |
| A5 preset top1000 finds the five quickstart ports | found [3001], missed [2223, 5673, 8787, 15673], other open: [8021, 8080]; 55 s, exit 0 | PARTIAL |

| B custom-network: PARTIAL (b1 48s/3 req) | Observed | Result |
|---|---|---|
| B1 all 7 ports found open; B3 CSV export: one row per service with the contract columns | B1: open: [2223, 3001, 5673, 8787, 8888, 15432, 15673] (48 s); B3: 7 rows, missing columns: none | PASS |
| B2a service name right on every port | 5/7; wrong: 8888=tcpwrapped, 15432=none | PARTIAL |
| B2b product/application recognised on every port | 2/7; not recognised: 8888 (httpbin; got ''), 15432 (PostgreSQL 16; got ''), 5673 (RabbitMQ 3.x AMQP; got 'Advanced Message Queue Protocol'), 15673 (RabbitMQ management UI; got 'Cowboy httpd'), 3001 (Gitea; got 'Golang net/http server') | PARTIAL |
| B2c admin interfaces flagged (finding kind admin-panel): 15673 | flagged 0/1; missing: 15673 findings=[] | FAIL |

| C modern: PARTIAL (c1 10s/8 req) | Observed | Result |
|---|---|---|
| C1 ports 80, 81, 443, 6379, 8080, 8081 found open; C2a service name right on every port; C3 8080: redirect to the WordPress installer is followed and r…; C4 443 speaks TLS but rejects the handshake without a configur…; C5 cookies and notable headers collected (phpMyAdmin cookie, X… | C1: open: [80, 81, 443, 6379, 8080, 8081] (10 s); C2a: 6/6; wrong: -; C3: status 200, title 'WordPress › Installation', redirect_chain ['http://host.docker.internal:8080/wp-admin/inst…; C4: service=https product='' http=null (contract: `service` stays `http`, `http.scheme` = https); C5: cookies {"80": [], "81": [], "8080": [], "8081": ["phpMyAdmin", "phpMyAdmin", "pma_lang", "phpMyAdmin"]}; hea… | PASS |
| C2b product/application recognised on every port | 3/5; not recognised: 8081 (phpMyAdmin; got 'Apache httpd'), 81 (Nginx Proxy Manager admin UI; got 'OpenResty web app server') | PARTIAL |
| C2c admin interfaces flagged (finding kind admin-panel): 8081, 81 | flagged 0/2; missing: 8081 findings=[], 81 findings=[] | FAIL |
| C6 notable headers/cookies are flagged as findings (kind interesting-header / interesting-cookie), e.g. X-Powere… | 0 such findings on 6 services | FAIL |

| D modern-proxy (Toxiproxy): PARTIAL (d1 14s/5 req, d2 16s/5 req, d3 15s/3 req) | Observed | Result |
|---|---|---|
| D1 export has a response time field for 8085; D2 with 500 ms latency the recorded response time is >= 500 ms; D4 with the timeout toxic (1000 ms) the scan still completes; D5 8085 is still recorded as an open service when its backend …; D7a service name right on every port | D1: no latency: {'ttfb_ms': 23, 'response_time_ms': 861}; D2: latency run: {'ttfb_ms': 522, 'response_time_ms': 1847} (baseline {'ttfb_ms': 23, 'response_time_ms': 861}); …; D4: exit 0 after 15 s (baseline 14 s); D5: 8085: state=open status=active; http Golang net/http server; HTTP 404 '' server=-; tech: -; findings: -; D7a: 3/3; wrong: - | PASS |
| D3 diff no-latency -> latency reports no change (only slower) | service_changed 8086 [http.tls.sha256] | FAIL |
| D6 diff no-latency -> timeout: no false change (nothing on 8086/8474, no 'missing'; a changed HTTP answer on 808… | service_changed 8085 [http.favicon_sha256,http.headers.cache-control,http.headers.content-type,http.headers.server,http.headers.vary,http.headers.x-content-type-options,http.headers.x-powered-by,http.redirect_chain,http.status_code,http.title,http.tls.sha256,… | FAIL |
| D8 plain-HTTP ports 8085/8086/8474 are fetched over http in every run (8086 = 301 to /dashboard/, title 'Traefik… | scheme per run: {"d1": {"8085": "http", "8086": "https", "8474": "http"}, "d2": {"8085": "http", "8086": "https", "8474": "http"}, "d3": {"8085": "https", "8086": "https", "8474": "http"}}; 8086 in d1: https://host.docker.internal:8086/ status 404 title '' tl… | FAIL |
| D7b product/application recognised on every port | 1/3; not recognised: 8086 (Traefik 3.1 dashboard; got 'Golang net/http server'), 8474 (Toxiproxy 2.12 API; got 'Golang net/http server') | PARTIAL |
| D7c admin interfaces flagged (finding kind admin-panel): 8086 | flagged 0/1; missing: 8086 findings=[] | FAIL |

| E vulnerable: PARTIAL (e1 20s/14 req) | Observed | Result |
|---|---|---|
| E1 21, 8088, 8089, 8090 found open (passive range 21000-21010 …; E2a service name right on every port | E1: open: [21, 8088, 8089, 8090, 21000, 21001, 21002, 21003, 21004, 21005, 21006, 21007, 21008, 21009, 21010] (20…; E2a: 4/4; wrong: - | PASS |
| E2b product/application recognised on every port | 1/4; not recognised: 21 (FTP vsftpd; got ''), 8089 (Adminer; got ''), 8090 (DVWA; got 'Apache httpd') | PARTIAL |
| E2c admin interfaces flagged (finding kind admin-panel): 8089 | flagged 0/1; missing: 8089 findings=[] | FAIL |
| E3 8088: WordPress version 4.7.x detected | http Apache httpd 2.4.10; HTTP 200 'WordPress › Installation' server=Apache/2.4.10 (Debian); tech: Apache 2.4.10, PHP 5.6.30, WordPress; findings: - | FAIL |
| E4 outdated finding for WordPress 4.7 on 8088 | outdated findings: none | FAIL |
| E5 outdated finding for the old PHP on 8088 | x-powered-by on 8088: 'PHP/5.6.30'; outdated findings on 8088: none | FAIL |
| E7 strictly non-intrusive: web access logs show only GET/HEAD from the scanner | methods ['GET', 'OPTIONS']; adminer: 6 requests, paths ['/', '/?CAVIT', '/favicon.ico', '/nice%20ports%2C/Tri%6Eity.txt%2ebak']; dvwa: 4 requests, paths ['/', '/favicon.ico', '/login.php']; wordpress: 4 requests, paths ['/', '/favicon.ico', '/wp-admin/install… | FAIL |

| F custom signature: PASS (f0 48s/3 req, f1 49s/3 req) | Observed | Result |
|---|---|---|
| F1 without the signature file: RabbitMQ UI / Gitea produce no …; F2 with --signatures-dir: the 3 custom findings appear (admin-…; F3 technology signature also yields a technologies entry with …; F4 diff before/after reports only findings/technologies change…; F5 a signature using POST is rejected with an error naming the… | F1: 15673: http Cowboy httpd; HTTP 200 'RabbitMQ Management' server=Cowboy; tech: -; findings: - / 3001: http Gol…; F2: findings: [(3001, 'agh-gitea', 'technology'), (3001, 'agh-gitea-cookie', 'interesting-cookie'), (15673, 'agh-…; F3: [{"name": "Gitea", "category": "devops", "version": "", "confidence": 90, "source": "signature:agh-gitea"}]; F4: service_changed 3001 [findings,technologies]; service_changed 15673 [findings]; F5: asi scan: --signatures-dir: /work/badsig/bad.yaml: signature "agh-bad-post" violates rule "methods GET and HE… | PASS |

| G import/export: PASS (no scan) | Observed | Result |
|---|---|---|
| G1 JSON export imports into a fresh database; G2 re-export equals the source: hosts, services, products, ver…; G3 HTTP details (headers, cookie names, TLS) survive the round…; G4 CSV export imports into a fresh database with the same serv… | G1: imported 1 hosts, 7 services as run import-20261121T194458.236124Z; 0 invalid rows; 1 changes; 0 left as stor…; G2: 1 hosts/7 services -> 1 hosts/7 services; differences: none; G3: differences: none; G4: imported 1 hosts, 7 services as run import-20261121T194458.657747Z; 0 invalid rows; 1 changes; 0 left as stor… | PASS |
## Defects
1. **No built-in findings: admin panels, outdated versions and notable headers/cookies are never flagged (only custom signatures produce findings)** (checks B2c, C2c, C6, D7c, E2c, E4, E5). Expected: admin interfaces flagged (finding kind admin-panel): 15673. Happened: B2c: flagged 0/1; missing: 15673 findings=[]; C2c: flagged 0/2; missing: 8081 findings=[], 81 findings=[]; C6: 0 such findings on 6 services; D7c: flagged 0/1; missing: 8086 findings=[]; E2c: flagged 0/1; missing: 8089 findings=[]; E4: outdated findings: none; E5: x-powered-by on 8088: 'PHP/5.6.30'; outdated findings on 8088: none. Command: `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports 2223,3001,5673,8787,8888,15432,15673 --name b1 --max-rate 300  --wait`. Output: `flagged 0/1; missing: 15673 findings=[]`
2. **Applications are not recognised as product/technology even when the title names them; versions missing (WordPress 4.7)** (checks B2b, C2b, D7b, E2b, E3). Expected: product/application recognised on every port. Happened: B2b: 2/7; not recognised: 8888 (httpbin; got ''), 15432 (PostgreSQL 16; got ''), 5673 (RabbitMQ 3.x AMQP; got 'Advanced Message Queue Protocol'), 15673 (R…; C2b: 3/5; not recognised: 8081 (phpMyAdmin; got 'Apache httpd'), 81 (Nginx Proxy Manager admin UI; got 'OpenResty web app server'); D7b: 1/3; not recognised: 8086 (Traefik 3.1 dashboard; got 'Golang net/http server'), 8474 (Toxiproxy 2.12 API; got 'Golang net/ht…. Command: `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports 2223,3001,5673,8787,8888,15432,15673 --name b1 --max-rate 300  --wait`. Output: `2/7; not recognised: 8888 (httpbin; got ''), 15432 (PostgreSQL 16; got ''), 5673 (RabbitMQ 3.x AMQP; got 'Advanced Message Queue Protocol'), 15673 (RabbitMQ management UI; got 'Cowboy httpd'), 3001 (Gitea; got 'Golang net/http se…`
3. **Service not identified: nmap runs with `--version-light` (PostgreSQL empty; plain `nmap -sV` says postgresql) and a port nmap calls tcpwrapped gets no HTTP probe (httpbin)** (checks B2a). Expected: service name right on every port. Happened: B2a: 5/7; wrong: 8888=tcpwrapped, 15432=none. Command: `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports 2223,3001,5673,8787,8888,15432,15673 --name b1 --max-rate 300  --wait`. Output: `{"port": 8888, "service": "tcpwrapped", "product": "", "http": null}; {"port": 15432, "service": "", "product": "", "http": null}`
4. **Ports that answer both TLS and plain HTTP (Traefik) are recorded over https: wrong content (404 instead of the dashboard) and false changes because the default cert changes on restart** (checks D8, D3, D6). Expected: plain-HTTP ports 8085/8086/8474 are fetched over http in every run (8086 = 301 to /dashboard/, title 'Traefik…. Happened: D8: scheme per run: {"d1": {"8085": "http", "8086": "https", "8474": "http"}, "d2": {"8085": "http", "8086": "https", "8474": "http"}, "d3": {"8085": "ht…; D3: service_changed 8086 [http.tls.sha256]; D6: service_changed 8085 [http.favicon_sha256,http.headers.cache-control,http.headers.content-type,http.headers.server,http.headers.vary,http.headers.x-c…. Command: `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports 8085,8086,8474 --name d1 --max-rate 300  --wait`. Output: `$ curl -si http://127.0.0.1:8086/ / head -2 HTTP/1.1 301 Moved Permanently Location: http://127.0.0.1:8086/dashboard/ $ curl -s http://127.0.0.1:8086/dashboard/ / grep -o '<title>.*</title>' <title>Traefik</title> $ curl -ski htt…`
5. **Not strictly GET/HEAD: nmap service detection sends OPTIONS and non-HTTP probes to ports it cannot identify** (checks E7). Expected: strictly non-intrusive: web access logs show only GET/HEAD from the scanner. Happened: E7: methods ['GET', 'OPTIONS']; adminer: 6 requests, paths ['/', '/?CAVIT', '/favicon.ico', '/nice%20ports%2C/Tri%6Eity.txt%2ebak']; dvwa: 4 requests, pa…. Command: `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports 21,8088,8089,8090,21000-21010 --name e1 --max-rate 300  --wait`. Output: `[Sat Nov 21 19:42:57 2026] [::ffff:172.23.0.1]:55814 [200]: OPTIONS /`
6. **Preset top1000 does not contain most of the organisers' ports** (checks A5). Expected: preset top1000 finds the five quickstart ports. Happened: A5: found [3001], missed [2223, 5673, 8787, 15673], other open: [8021, 8080]; 55 s, exit 0. Command: `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports top1000 --name a-top1000 --max-rate 300  --wait`. Output: ` --ports top1000 --name a-top1000 --max-rate 300  --wait run a-top1000 status=completed groups=1 addresses=1 hosts=1 exit=0 run a-top1000 status=completed started=2026-11-21T19:26:35Z finished=2026-11-21T19:27:29Z groups=1 addres…`
## Recognition table (svc/prod/ver/admin/outdated: Y, N, - = not applicable)
| Port | Truth | ASI: service / product version | Technologies | Findings | svc/prod/ver/admin/outdated |
|---|---|---|---|---|---|
| 8888 | httpbin (HTTP, gunicorn 19.9) | tcpwrapped / -  | - | - | N/N/N/-/- |
| 15432 | PostgreSQL 16 | none / -  | - | - | N/N/N/-/- |
| 5673 | RabbitMQ 3.x AMQP | amqp / Advanced Message Queue Protocol  | - | - | Y/N/N/-/- |
| 15673 | RabbitMQ management UI (admin) | http / Cowboy httpd  | - | - | Y/N/-/N/- |
| 3001 | Gitea (web) | http / Golang net/http server  | - | - | Y/N/-/-/- |
| 2223 | Gitea SSH (OpenSSH) | ssh / OpenSSH 10.3 | - | - | Y/Y/Y/-/- |
| 8787 | nginx | http / nginx 1.31.9 | nginx 1.31.9 | - | Y/Y/Y/-/- |
| 8080 | WordPress (fresh, installer redirect) | http / Apache httpd 2.4.71 | Apache 2.4.71, PHP 8.3.37, WordPress  | - | Y/Y/N/-/- |
| 8081 | phpMyAdmin (admin) | http / Apache httpd 2.4.71 | Apache 2.4.71, PHP 8.3.37 | - | Y/N/N/N/- |
| 6379 | Redis 7 | redis / Redis key-value store 7.4.12 | - | - | Y/Y/Y/-/- |
| 80 | Nginx Proxy Manager default site (openresty) | http / OpenResty web app server  | - | - | Y/Y/-/-/- |
| 81 | Nginx Proxy Manager admin UI (admin) | http / OpenResty web app server  | - | - | Y/N/-/N/- |
| 443 | Nginx Proxy Manager TLS (rejects handshake w… | https / -  | - | - | Y/-/-/-/- |
| 8085 | WordPress behind Traefik+Toxiproxy | http / Apache httpd 2.4.71 | Apache 2.4.71, PHP 8.3.37, WordPress  | - | Y/Y/-/-/- |
| 8086 | Traefik 3.1 dashboard (admin) | http / Golang net/http server  | - | - | Y/N/N/N/- |
| 8474 | Toxiproxy 2.12 API | http / Golang net/http server  | - | - | Y/N/N/-/- |
| 21 | FTP vsftpd | ftp / -  | - | - | Y/N/N/-/- |
| 8088 | WordPress 4.7 on old PHP (outdated) | http / Apache httpd 2.4.10 | Apache 2.4.10, PHP 5.6.30, WordPress  | - | Y/Y/N/-/0/2 |
| 8089 | Adminer (admin) | http / -  | PHP 8.4.28 | - | Y/N/N/N/- |
| 8090 | DVWA | http / Apache httpd 2.4.25 | Apache 2.4.25, PHP  | - | Y/N/-/-/- |
