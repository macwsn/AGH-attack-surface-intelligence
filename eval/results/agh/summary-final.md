# ASI (`8ceb709`) vs nmap on the organisers' stacks
Image built from `git archive 8ceb709`. Target `host.docker.internal`, ports published on 127.0.0.1, one stack at a time. nmap: the same binary inside the ASI container, `nmap -Pn -sT -sV [--version-light] -p <same ports>`. Flags are service/product/version right (Y/N, - = no truth).

| Totals | ASI | nmap --version-light | nmap default |
|---|---|---|---|
| Service names right | 20/20 | 18/20 | 19/20 |
| Products recognised | 17/19 | 4/19 | 6/19 |
| Versions right | 10/13 | 3/13 | 4/13 |
| Admin panels flagged | 4/5 | 0/5 | 0/5 |
| Outdated flagged | 2/2 | 0/2 | 0/2 |

| Stack | Products ASI / light / default | Versions ASI / light / default | False changes (scan twice) | Wall-clock s: ASI scan 1, 2 / nmap light / nmap default |
|---|---|---|---|---|
| custom-network | 7/7 / 2/7 / 4/7 | 4/5 / 2/5 / 3/5 | 0 | 61, 61 / 48 / 49 |
| modern | 5/5 / 2/5 / 2/5 | 3/3 / 1/3 / 1/3 | 0 | 16, 15 / 7 / 6 |
| modern-proxy | 2/3 / 0/3 / 0/3 | 1/2 / 0/2 / 0/2 | 0 | 21, 21 / 13 / 13 |
| vulnerable | 3/4 / 0/4 / 0/4 | 2/3 / 0/3 / 0/3 | 0 | 33, 33 / 18 / 20 |

| custom-network: port | Truth | ASI: service / product version; technologies; findings | nmap light | nmap default | ASI | light | default |
|---|---|---|---|---|---|---|---|
| 8888 | httpbin 0.9.2 (HTTP, gunicorn 19.9) | http / - ; httpbin 0.9.2, Python , React , Swagger UI , gunicorn 19.9.0, jQuery ; builtin-httpbin[technology], builtin-header-server[interesting-header] | tcpwrapped / -  | tcpwrapped / -  | Y/Y/Y | N/N/N | N/N/N |
| 15432 | PostgreSQL 16 | postgresql / PostgreSQL DB 9.6.0 or later; PostgreSQL ; - | none / -  | postgresql / PostgreSQL DB 9.6.0 or later | Y/Y/N | N/N/N | Y/Y/N |
| 5673 | RabbitMQ 3.x AMQP | amqp / RabbitMQ 3.13.7; RabbitMQ 3.13.7; - | amqp / Advanced Message Queue Protocol  | amqp / RabbitMQ 3.13.7 (0-9) | Y/Y/Y | Y/N/N | Y/Y/Y |
| 15673 | RabbitMQ management UI (admin) | http / Cowboy httpd ; RabbitMQ , Bootstrap , Cowboy , Erlang , jQuery 3.5.1; builtin-rabbitmq-management[technology], builtin-rabbitmq-management-ui[admin-panel] | http / Cowboy httpd  | http / Cowboy httpd  | Y/Y/- | Y/N/- | Y/N/- |
| 3001 | Gitea (web) | http / Golang net/http server ; Gitea 28.4.0, Go ; builtin-gitea[technology], builtin-unfinished-installation[admin-panel] | http / Golang net/http server  | http / Golang net/http server  | Y/Y/- | Y/N/- | Y/N/- |
| 2223 | Gitea SSH (OpenSSH) | ssh / OpenSSH 10.3; OpenSSH 10.3; - | ssh / OpenSSH 10.3 (protocol 2.0) | ssh / OpenSSH 10.3 (protocol 2.0) | Y/Y/Y | Y/Y/Y | Y/Y/Y |
| 8787 | nginx | http / nginx 1.31.9; nginx 1.31.9; builtin-header-server[interesting-header] | http / nginx 1.31.9 | http / nginx 1.31.9 | Y/Y/Y | Y/Y/Y | Y/Y/Y |

| modern: port | Truth | ASI: service / product version; technologies; findings | nmap light | nmap default | ASI | light | default |
|---|---|---|---|---|---|---|---|
| 8080 | WordPress (fresh, installer redirect) | http / Apache httpd 2.4.71; WordPress 7.1.5, Apache 2.4.71, PHP 8.3.37, Debian , jQuery , jQuery Migrate 3.4.1; builtin-wordpress-install[technology], builtin-header-x-powered-by[interesting-header], builtin-header-server[interesting-header], builtin-unfinished-installation[admin-panel] | http / Apache httpd 2.4.71 ((Debian)) | http / Apache httpd 2.4.71 ((Debian)) | Y/Y/Y | Y/N/N | Y/N/N |
| 8081 | phpMyAdmin (admin) | http / Apache httpd 2.4.71; phpMyAdmin 5.2.3, Apache 2.4.71, PHP 8.3.37, Bootstrap , Debian , jQuery , jQuery Migrate , jQuery UI ; builtin-phpmyadmin[technology], builtin-phpmyadmin-login[admin-panel], builtin-header-x-powered-by[interesting-header], builtin-header-server[interesting-header], builtin-cookie-stack[interesting-c… | http / Apache httpd 2.4.71 ((Debian)) | http / Apache httpd 2.4.71 ((Debian)) | Y/Y/Y | Y/N/N | Y/N/N |
| 6379 | Redis 7 | redis / Redis key-value store 7.4.12; Redis 7.4.12; - | redis / Redis key-value store 7.4.12 | redis / Redis key-value store 7.4.12 | Y/Y/Y | Y/Y/Y | Y/Y/Y |
| 80 | Nginx Proxy Manager default site (openr… | http / OpenResty web app server ; Bootstrap 3.4.1, OpenResty , nginx ; - | http / OpenResty web app server  | http / OpenResty web app server  | Y/Y/- | Y/Y/- | Y/Y/- |
| 81 | Nginx Proxy Manager admin UI (admin) | http / OpenResty web app server ; Nginx Proxy Manager , OpenResty , nginx ; builtin-nginx-proxy-manager[technology], builtin-nginx-proxy-manager-ui[admin-panel] | http / OpenResty web app server  | http / OpenResty web app server  | Y/Y/- | Y/N/- | Y/N/- |
| 443 | Nginx Proxy Manager TLS (rejects handsh… | http / openresty ; -; - | ssl/https / -  | ssl/https / openresty  | Y/-/- | Y/-/- | Y/-/- |

| modern-proxy: port | Truth | ASI: service / product version; technologies; findings | nmap light | nmap default | ASI | light | default |
|---|---|---|---|---|---|---|---|
| 8085 | WordPress behind Traefik+Toxiproxy | http / Apache httpd 2.4.71; WordPress 7.1.5, Apache 2.4.71, PHP 8.3.37, Debian , jQuery , jQuery Migrate 3.4.1; builtin-wordpress-install[technology], builtin-header-x-powered-by[interesting-header], builtin-header-server[interesting-header], builtin-unfinished-installation[admin-panel] | http / Apache httpd 2.4.71 ((Debian)) | http / Apache httpd 2.4.71 ((Debian)) | Y/Y/- | Y/N/- | Y/N/- |
| 8086 | Traefik 3.1 dashboard (admin) | http / Golang net/http server ; -; - | ssl/http / Golang net/http server (Go-IPFS json-rpc or Infl… | ssl/http / Golang net/http server (Go-IPFS json-rpc or Infl… | Y/N/N | Y/N/N | Y/N/N |
| 8474 | Toxiproxy 2.12 API | http / Golang net/http server ; Toxiproxy 2.12.0; builtin-toxiproxy[technology] | http / Golang net/http server (Go-IPFS json-rpc or InfluxDB… | http / Golang net/http server (Go-IPFS json-rpc or InfluxDB… | Y/Y/Y | Y/N/N | Y/N/N |

| vulnerable: port | Truth | ASI: service / product version; technologies; findings | nmap light | nmap default | ASI | light | default |
|---|---|---|---|---|---|---|---|
| 21 | FTP vsftpd | ftp / - ; -; - | ftp / -  | ftp / -  | Y/N/N | Y/N/N | Y/N/N |
| 8088 | WordPress 4.7 on old PHP (outdated) | http / Apache httpd 2.4.10; WordPress 4.7.5, Apache 2.4.10, PHP 5.6.30, Debian , jQuery , jQuery Migrate 1.4.1; builtin-wordpress-install[technology], builtin-header-x-powered-by[interesting-header], builtin-header-server[interesting-header], builtin-unfinished-installation[admin-panel], outdated-wordpress[outdated], outdated-a… | http / Apache httpd 2.4.10 ((Debian)) | http / Apache httpd 2.4.10 ((Debian)) | Y/Y/Y | Y/N/N | Y/N/N |
| 8089 | Adminer (admin) | http / - ; Adminer 6.3.0, PHP 8.4.28; builtin-adminer[technology], builtin-adminer-login[admin-panel], builtin-header-x-powered-by[interesting-header] | http / - (PHP 8.4.28) | http / - (PHP 8.4.28) | Y/Y/Y | Y/N/N | Y/N/N |
| 8090 | DVWA | http / Apache httpd 2.4.25; DVWA 1.10, Apache 2.4.25, PHP , Debian ; builtin-dvwa[technology], builtin-header-server[interesting-header], builtin-cookie-stack[interesting-cookie], builtin-cookie-no-httponly[interesting-cookie], builtin-login-form[admin-panel], outdated-apache[outdated] | http / Apache httpd 2.4.25 ((Debian)) | http / Apache httpd 2.4.25 ((Debian)) | Y/Y/- | Y/N/- | Y/N/- |

## Against run3 (`b4f6593`)
Scores run3 -> final: products_recognised 17/19 -> 17/19, service_names_right 20/20 -> 20/20, versions_right 10/13 -> 10/13, admin_panels_flagged 5/5 -> 4/5, outdated_flagged 2/2 -> 2/2.
Regressed checks (PASS before, not now):
- I1 FAIL: expected quickstart scan of 5 explicit ports takes under 20 s (was 48 s); observed a1 59 s, a2 58 s, a3 59 s; command `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports 2223,3001,5673,8787,15673 --name a1 --max-rate 300  --wait`; output `run a1 status=completed started=2026-11-22T01:21:06Z finished=2026-11-22T01:22:05Z mode=full packets=25 requests_measured=12 nmap_packets_estimated=13 max_rate=300 adaptive=true actual_peak=0.2/s actual_avg=0.1/s actual_chart=▁▁ limit_chart=██ group…`
- D3 FAIL: expected diff no-latency -> latency reports no change (only slower); observed service_changed 8086 [http.tls.sha256]; command `docker compose -p asi-agh-prod exec -T asi asi diff --from d1 --to d2 --format json --out FILE`; output `[{"type": "service_changed", "address": "192.168.65.254", "port": 8086, "protocol": "tcp", "fields": [{"field": "http.tls.sha256", "old": "00c64108e0fdb84af3fb1748b781c78ffa0f6b4266456df805a623aed5c9e21d", "new": "0bd0806b83006a19ece8d1658747cb981ad…`
- D6 FAIL: expected diff no-latency -> timeout: no false change (nothing on 8086/8474, no 'missing'; a changed HTTP answer on 808…; observed service_changed 8085 [findings,http.favicon_sha256,http.headers.cache-control,http.headers.content-type,http.headers.server,http.headers.vary,http.headers.x-content-type-options,http.headers.x-powered-by,http.redirect_chain,http.status_code,http.title,http.tls.sha256,product,technologies,version]; …; command `docker compose -p asi-agh-prod exec -T asi asi diff --from d1 --to d3 --format json --out FILE`; output `[{"type": "service_changed", "address": "192.168.65.254", "port": 8085, "protocol": "tcp", "fields": [{"field": "findings", "old": ["builtin-header-server", "builtin-header-x-powered-by", "builtin-unfinished-installation", "builtin-wordpress-install…`
- D8 FAIL: expected plain-HTTP ports 8085/8086/8474 are fetched over http in every run (8086 = 301 to /dashboard/, title 'Traefik…; observed scheme per run: {"d1": {"8085": "http", "8086": "https", "8474": "http"}, "d2": {"8085": "http", "8086": "https", "8474": "http"}, "d3": {"8085": "https", "8086": "https", "8474": "http"}}; 8086 in d1: https://host.docker.internal:8086/ status 404 title '' tls.subject_cn 'TRAEFIK DEFAULT CERT'; command `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports 8085,8086,8474 --name d1 --max-rate 300  --wait`; output `$ curl -si http://127.0.0.1:8086/ / head -2 HTTP/1.1 301 Moved Permanently Location: http://127.0.0.1:8086/dashboard/ $ curl -s http://127.0.0.1:8086/dashboard/ / grep -o '<title>.*</title>' <title>Traefik</title> $ curl -ski https://127.0.0.1:8086/…`
- D7b PARTIAL: expected product/application recognised on every port; observed 2/3; not recognised: 8086 (Traefik 3.1 dashboard; got 'Golang net/http server'); command `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports 8085,8086,8474 --name d1 --max-rate 300  --wait`; output ``
- D7c FAIL: expected admin interfaces flagged (finding kind admin-panel): 8086; observed flagged 0/1; missing: 8086 findings=[]; command `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports 8085,8086,8474 --name d1 --max-rate 300  --wait`; output ``
- E7 FAIL: expected strictly non-intrusive: web access logs show only GET/HEAD from the scanner; observed methods ['GET', 'OPTIONS', 'POST']; adminer: 16 requests, paths ['/', '/?CAVIT', '/HNAP1', '/Nmap/folder/check1795311520', '/NmapUpperCheck1795311520', '/api/version', '/evox/about', '/favicon.ico', '/nice%20ports%2C/Tri%6Eity.txt%2ebak', '/nmaplowercheck1795311520', '/sdk', '/version']; dvwa: 6 re…; command `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports 21,8088,8089,8090,21000-21010 --name e1 --max-rate 300  --wait`; output `[Sun Nov 22 01:38:32 2026] [::ffff:172.20.0.1]:55696 [200]: OPTIONS / / [Sun Nov 22 01:38:40 2026] [::ffff:172.20.0.1]:55832 [200]: POST /sdk`
- G2 PARTIAL: expected re-export equals the source: hosts, services, products, versions, technologies, findings; observed 1 hosts/7 services -> 1 hosts/7 services; differences: 15673 findings: ['builtin-rabbitmq-management', 'builtin-rabbitmq-management-ui'] -> ['builtin-heuristic-title', 'builtin-rabbitmq-management', 'builtin-rabbitmq-management-ui']; command `docker compose -p asi-agh-prod exec -T asi asi export --format json --out /out/G/reexport.json`; output ``
Recognition flags that dropped: modern-proxy:8086 product_recognised Y -> N; modern-proxy:8086 version_right Y -> N; modern-proxy:8086 admin_flagged Y -> N.
Checks fixed since run3: B2b, F3. Still failing: I1 (FAIL), A5 (PARTIAL), D3 (FAIL), D6 (FAIL), D8 (FAIL), D7b (PARTIAL), D7c (FAIL), E2b (PARTIAL), E7 (FAIL), G2 (PARTIAL), H3 (PARTIAL).
Durations (s) / requests in target logs: a1 59/5 (was 11); a2 58/0 (was 10); a3 59/5 (was 11); a-range 66/5 (was 18); a-top1000 65/0 (was 17); b1 61/5 (was 19); b1b 61/5 (was -); c1 16/13 (was 15); c1b 15/13 (was -); d1 21/8 (was 9); d1b 21/7 (was 9); d2 26/9 (was 13); d3 23/4 (was 11); e1 33/30 (was 15); e1b 33/31 (was -); f0 60/5 (was 11); f1 60/5 (was 12); h1 62/5 (was 20); h2 62/5 (was 20); h3 60/0 (was 19)

## Notes
- **Safety regression (E7)**: the second service pass runs `nmap -Pn -sT -sV -p <unidentified ports>` at default intensity, which also runs nmap's version-category scripts. During ASI scan e1 the Adminer log shows `OPTIONS /` and `POST /sdk`, plus `/HNAP1`, `/evox/about`, `/nmaplowercheck…`. Run 3 logged GET only. Seen in-process: `nmap -Pn -sT -sV -p 3001,5673 --max-rate 150 -n -oX - 192.168.65.254`.
- **Duration regression (I1)**: the same second pass adds about 48 s on the custom-network stack (quickstart 59 s, was 11 s; full stack 61 s, was 19 s); plain nmap needs 48 s there on its own.
- **Traefik regression (D8, D3, D7b, D7c)**: 8086 is again fetched over https (404, TRAEFIK DEFAULT CERT), so the dashboard, its version and its admin-panel finding are lost (admin panels 5/5 -> 4/5) and a restart of the stack shows up as `service_changed 8086 [http.tls.sha256]`. Two scans without a restart still give an empty diff.
- **Import (G2, new)**: importing the JSON export adds a finding the scan did not have (`builtin-heuristic-title` on 15673), so export -> import -> export is no longer identical.
- Improved since run 3: RabbitMQ AMQP 5673 is now `RabbitMQ 3.13.7`; a custom technology signature keeps its own `technologies` entry (F3); PostgreSQL no longer gets the wrong technology version 9.6.0 (the product version string is still nmap's "9.6.0 or later"). vsftpd on 21 is still not identified by ASI or by either nmap mode.
- False changes on an unchanged stack (two consecutive scans): 0 on all four stacks, including the Adminer CSP nonce and favicon.
- Harness note: on the first attempt at the modern stack Docker's forwarder reset connections to host port 81 (the service answered inside the container); the scenario was re-run and the saved results are from the clean run.
