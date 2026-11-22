# ASI vs lab-agh: Run 1 (`efeab4e`) / Run 2 (`49e0f42`) / Run 3 (`b4f6593`)
Scenarios in the last run: A=PARTIAL B=PARTIAL C=PASS D=PASS E=PARTIAL F=PARTIAL G=PASS H=PARTIAL. Remaps: {}.

| Score | Run 1 (`efeab4e`) | Run 2 (`49e0f42`) | Run 3 (`b4f6593`) |
|---|---|---|---|
| Products recognised | 7/19 | 14/19 | 17/19 |
| Versions right | 3/13 | 8/13 | 10/13 |
| Admin panels flagged | 0/5 | 4/5 | 5/5 |
| Outdated flagged | 0/2 | 2/2 | 2/2 |
| Service names right | 18/20 | 18/20 | 20/20 |

Notable header/cookie findings per stack (last run): custom-network: 2 interesting-header, 0 interesting-cookie; modern: 4 interesting-header, 1 interesting-cookie; modern-proxy: 2 interesting-header, 0 interesting-cookie; vulnerable: 4 interesting-header, 2 interesting-cookie.

## Recognition (flags: service/product/version/admin/outdated; · = not scanned)
| Port | Truth | Last run: service / product version | Technologies | Findings [kind] | R1 | R2 | R3 |
|---|---|---|---|---|---|---|---|
| 8888 | httpbin (HTTP, gunicorn 19.9) | http / -  | httpbin 0.9.2 | builtin-httpbin[technology], builtin-header-server[interesting-header] | N/N/N/-/- | N/N/N/-/- | Y/Y/Y/-/- |
| 15432 | PostgreSQL 16 | postgresql / PostgreSQL DB 9.6.0 or later | PostgreSQL 9.6.0 | - | N/N/N/-/- | N/N/N/-/- | Y/Y/N/-/- |
| 5673 | RabbitMQ 3.x AMQP | amqp / Advanced Message Queue Protocol  | - | - | Y/N/N/-/- | Y/N/N/-/- | Y/N/N/-/- |
| 15673 | RabbitMQ management UI (admin) | http / Cowboy httpd  | RabbitMQ  | builtin-rabbitmq-management[technology], builtin-rabbitmq-management-ui[admin-panel] | Y/N/-/N/- | Y/Y/-/Y/- | Y/Y/-/Y/- |
| 3001 | Gitea (web) | http / Golang net/http server  | Gitea 28.4.0 | builtin-gitea[technology], builtin-login-form[admin-panel] | Y/N/-/-/- | Y/Y/-/-/- | Y/Y/-/-/- |
| 2223 | Gitea SSH (OpenSSH) | ssh / OpenSSH 10.3 | OpenSSH 10.3 | - | Y/Y/Y/-/- | Y/Y/Y/-/- | Y/Y/Y/-/- |
| 8787 | nginx | http / nginx 1.31.9 | nginx 1.31.9 | builtin-header-server[interesting-header] | Y/Y/Y/-/- | Y/Y/Y/-/- | Y/Y/Y/-/- |
| 8080 | WordPress (fresh, installer redirect) | http / Apache httpd 2.4.71 | WordPress 7.1.5, Apache 2.4.71, PHP 8.3.37 | builtin-wordpress-install[technology], builtin-header-x-powered-by[interesting-header], builtin-header-server[interesting-header] | Y/Y/N/-/- | Y/Y/Y/-/- | Y/Y/Y/-/- |
| 8081 | phpMyAdmin (admin) | http / Apache httpd 2.4.71 | phpMyAdmin 5.2.3, Apache 2.4.71, PHP 8.3.37 | builtin-phpmyadmin[technology], builtin-phpmyadmin-login[admin-panel], builtin-header-x-powered-by[interesting-header], builtin-header-server[interesting-header], builtin-cookie-stack[interesting-cookie] | Y/N/N/N/- | Y/Y/Y/Y/- | Y/Y/Y/Y/- |
| 6379 | Redis 7 | redis / Redis key-value store 7.4.12 | Redis 7.4.12 | - | Y/Y/Y/-/- | Y/Y/Y/-/- | Y/Y/Y/-/- |
| 80 | Nginx Proxy Manager default site (openres… | http / OpenResty web app server  | - | - | Y/Y/-/-/- | Y/Y/-/-/- | Y/Y/-/-/- |
| 81 | Nginx Proxy Manager admin UI (admin) | http / OpenResty web app server  | Nginx Proxy Manager  | builtin-nginx-proxy-manager[technology], builtin-nginx-proxy-manager-ui[admin-panel] | Y/N/-/N/- | Y/Y/-/Y/- | Y/Y/-/Y/- |
| 443 | Nginx Proxy Manager TLS (rejects handshak… | http / openresty  | - | - | Y/-/-/-/- | Y/-/-/-/- | Y/-/-/-/- |
| 8085 | WordPress behind Traefik+Toxiproxy | http / Apache httpd 2.4.71 | WordPress 7.1.5, Apache 2.4.71, PHP 8.3.37 | builtin-wordpress-install[technology], builtin-header-x-powered-by[interesting-header], builtin-header-server[interesting-header] | Y/Y/-/-/- | Y/Y/-/-/- | Y/Y/-/-/- |
| 8086 | Traefik 3.1 dashboard (admin) | http / Golang net/http server  | Traefik 3.1.7 | builtin-traefik-dashboard[technology], builtin-traefik-dashboard-ui[admin-panel], builtin-traefik-api[technology] | Y/N/N/N/- | Y/N/N/N/- | Y/Y/Y/Y/- |
| 8474 | Toxiproxy 2.12 API | http / Golang net/http server  | Toxiproxy 2.12.0 | builtin-toxiproxy[technology] | Y/N/N/-/- | Y/Y/Y/-/- | Y/Y/Y/-/- |
| 21 | FTP vsftpd | ftp / -  | - | - | Y/N/N/-/- | Y/N/N/-/- | Y/N/N/-/- |
| 8088 | WordPress 4.7 on old PHP (outdated) | http / Apache httpd 2.4.10 | WordPress 4.7.5, Apache 2.4.10, PHP 5.6.30 | builtin-wordpress-install[technology], builtin-header-x-powered-by[interesting-header], builtin-header-server[interesting-header], outdated-wordpress[outdated], outdated-apache[outdated], outdated-php[outdated] | Y/Y/N/-/0/2 | Y/Y/Y/-/2/2 | Y/Y/Y/-/2/2 |
| 8089 | Adminer (admin) | http / -  | Adminer 6.3.0, PHP 8.4.28 | builtin-adminer[technology], builtin-adminer-login[admin-panel], builtin-header-x-powered-by[interesting-header] | Y/N/N/N/- | Y/Y/Y/Y/- | Y/Y/Y/Y/- |
| 8090 | DVWA | http / Apache httpd 2.4.25 | DVWA 1.10, Apache 2.4.25, PHP  | builtin-dvwa[technology], builtin-header-server[interesting-header], builtin-cookie-stack[interesting-cookie], builtin-cookie-no-httponly[interesting-cookie], builtin-login-form[admin-panel], outdated-apache[outdated] | Y/N/-/-/- | Y/Y/-/-/- | Y/Y/-/-/- |

## Earlier defects
1. **No admin-panel / outdated findings out of the box**: fixed. B2c FAIL->PASS->PASS (flagged 1/1; missing: -); C2c FAIL->PASS->PASS (flagged 2/2; missing: -); D7c FAIL->FAIL->PASS (flagged 1/1; missing: -); E2c FAIL->PASS->PASS (flagged 1/1; missing: -); E4 FAIL->PASS->PASS (outdated findings: {"8088": ["Outdated WordPress 4.7.5 (WordPress 4.7.5 is older than the minimum supported version 6.0 (support table checked 2026-11-21))", "Outdated A…); E5 FAIL->PASS->PASS (x-powered-by on 8088: 'PHP/5.6.30'; outdated findings on 8088: ['Outdated WordPress 4.7.5 (WordPress 4.7.5 is older than the minimum supported version 6.0 (support table…)
2. **No interesting-header / interesting-cookie findings**: fixed. C6 FAIL->FAIL->PASS (5 such findings on 6 services)
3. **Applications not recognised as product/technology; versions missing**: changed. B2b PARTIAL->PARTIAL->PARTIAL (6/7; not recognised: 5673 (RabbitMQ 3.x AMQP; got 'Advanced Message Queue Protocol')); C2b PARTIAL->PASS->PASS (5/5; not recognised: -); D7b PARTIAL->PARTIAL->PASS (3/3; not recognised: -); E2b PARTIAL->PARTIAL->PARTIAL (3/4; not recognised: 21 (FTP vsftpd; got '')); E3 FAIL->PASS->PASS (http Apache httpd 2.4.10; HTTP 200 'WordPress › Installation' server=Apache/2.4.10 (Debian); tech: WordPress 4.7.5, Apache 2.4.10, PHP 5.6.30; findings: builtin-wordpres…)
4. **Service not identified (PostgreSQL empty, httpbin tcpwrapped and not probed)**: fixed. B2a PARTIAL->PARTIAL->PASS (7/7; wrong: -)
5. **Traefik dual TLS/HTTP ports recorded over https; false diff changes**: fixed. D8 FAIL->FAIL->PASS (scheme per run: {"d1": {"8085": "http", "8086": "http", "8474": "http"}, "d2": {"8085": "http", "8086": "http", "8474": "http"}, "d3": {"8085": "http", "8086": "http", "…); D9 ·->·->PASS (no changes); D3 FAIL->FAIL->PASS (no changes); D6 FAIL->·->PASS (service_changed 8085 [findings,http.favicon_sha256,http.headers.cache-control,http.headers.content-type,http.headers.server,http.headers.vary,http.headers.x-powered-by,h…)
6. **nmap sends OPTIONS / non-HTTP probes (not strictly GET/HEAD)**: fixed. E7 FAIL->FAIL->PASS (methods ['GET']; adminer: 5 requests, paths ['/', '/api/version', '/favicon.ico', '/version']; dvwa: 6 requests, paths ['/', '/api/version', '/favicon.ico', '/login.php'…)
7. **top1000 misses the organisers' ports**: changed. A5 PARTIAL->·->PARTIAL (found [3001], missed [2223, 5673, 8787, 15673], other open: [8021]; 17 s, exit 0)
8. **443 (TLS handshake rejected) exported as service https with http null**: fixed. C4 PASS->PASS->PASS (service=http product='openresty' http={"scheme": "https", "url": "https://host.docker.internal/", "status_code": 0, "title": "", "headers": {}, "cookies": [], (contract:…)
9. **Quickstart scan of 5 ports takes 48 s**: fixed. I1 ·->·->PASS (a1 11 s, a2 10 s, a3 11 s)

## New in the last run
- check F3 FAIL: expected technology signature also yields a technologies entry with source signature:<id>; observed no such technologies entry on 3001; command `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports 2223,3001,5673,8787,15673 --name f1 --max-rate 300 --signatures-dir /work/signatures --wait`; output ``
- check H3 PARTIAL: expected recheck is faster than the full scan; observed 20 s vs 20 s; command `docker compose -p asi-agh-prod exec -T asi asi scan run --targets-file /work/targets.txt --ports 2223,3001,5673,8787,8888,15432,15673 --name h2 --max-rate 300 --mode recheck --wait`; output ``
- **PostgreSQL version taken from nmap's "9.6.0 or later"** (new, minor): 15432 is now identified (`postgresql / PostgreSQL DB`), but the export has `"version": "9.6.0 or later"` and a technology `PostgreSQL 9.6.0` (confidence 80) while the server is 16.x. A lower bound is presented as the version and could later trigger a false `outdated`. Repro: `asi scan run --targets-file /work/targets.txt --ports 15432 --name b1 --max-rate 300 --wait`, then `asi export --format json`.
- **F3** (new, minor, contract §2): a custom `technology` signature whose name equals a built-in one (`agh-gitea` vs `builtin-gitea`, both "Gitea") produces its finding but no `technologies` entry with `source: "signature:agh-gitea"`; only the built-in entry is kept. Run 1 (no pack) had the entry.
- **H3** (observation): on this single host `--mode recheck` is not faster than the full scan (h1 20 s, h2 20 s, h3 19 s; `packets=33`). It is correct: same 7 services, empty diff, then exactly `service_missing 8787`. Target logs show the same 5 GETs on nginx 8787 as the full scan (other services keep no access log).
- vsftpd did not crash in this run; port 21 was scanned: service `ftp`, still no product/version (the second nmap pass does not identify vsftpd). RabbitMQ AMQP 5673 is still generic. top1000 still finds only 3001 (unchanged by design).
- 443: now `service: http`, `product: openresty`, `http.scheme: https`, `status_code: 0` (handshake rejected by the server). Timeout toxic: 8085 recorded as `http-proxy`, HTTP 502 over plain http (correct). Latency: ttfb 8 -> 515 ms, response time 765 -> 1793 ms.
- Truth table change: httpbin's version is accepted as 0.9.2 (what the app reports) or gunicorn 19.9; runs 1 and 2 reported neither, so their scores do not move.

## Scan durations (s) and requests seen in target logs, last run
a1 11s/5; a2 10s/0; a3 11s/5; a-range 18s/5; a-top1000 17s/0; b1 19s/5; c1 15s/13; d1 9s/8; d1b 9s/8; d2 13s/9; d3 11s/5; e1 15s/19; f0 11s/5; f1 12s/5; h1 20s/5; h2 20s/5; h3 19s/0
