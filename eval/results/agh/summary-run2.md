# ASI vs lab-agh: run 2 (`49e0f42`) against run 1 (`efeab4e`)
Scenarios run 2: A=PASS B=PARTIAL C=PARTIAL D=PARTIAL E=PARTIAL. Remaps: {}.

| Score | Run 1 | Run 2 |
|---|---|---|
| Products recognised | 7/19 | 14/19 |
| Versions right | 3/13 | 8/13 |
| Admin panels flagged | 0/5 | 4/5 |
| Outdated flagged | 0/2 | 2/2 |
| Service names right | 18/20 | 18/20 |

## Recognition (flags: service/product/version/admin/outdated)
| Port | Truth | Run 2: service / product version | Technologies | Findings [kind] | Run 1 | Run 2 |
|---|---|---|---|---|---|---|
| 8888 | httpbin (HTTP, gunicorn 19.9) | tcpwrapped / -  | - | - | N/N/N/-/- | N/N/N/-/- |
| 15432 | PostgreSQL 16 | none / -  | - | - | N/N/N/-/- | N/N/N/-/- |
| 5673 | RabbitMQ 3.x AMQP | amqp / Advanced Message Queue Protocol  | - | - | Y/N/N/-/- | Y/N/N/-/- |
| 15673 | RabbitMQ management UI (admin) | http / Cowboy httpd  | RabbitMQ  | builtin-rabbitmq-management[technology], builtin-rabbitmq-management-ui[admin-panel] | Y/N/-/N/- | Y/Y/-/Y/- |
| 3001 | Gitea (web) | http / Golang net/http server  | Gitea 28.4.0 | builtin-gitea[technology] | Y/N/-/-/- | Y/Y/-/-/- |
| 2223 | Gitea SSH (OpenSSH) | ssh / OpenSSH 10.3 | OpenSSH 10.3 | - | Y/Y/Y/-/- | Y/Y/Y/-/- |
| 8787 | nginx | http / nginx 1.31.9 | nginx 1.31.9 | - | Y/Y/Y/-/- | Y/Y/Y/-/- |
| 8080 | WordPress (fresh, installer redirect) | http / Apache httpd 2.4.71 | WordPress 7.1.5, Apache 2.4.71, PHP 8.3.37 | builtin-wordpress-install[technology] | Y/Y/N/-/- | Y/Y/Y/-/- |
| 8081 | phpMyAdmin (admin) | http / Apache httpd 2.4.71 | phpMyAdmin 5.2.3, Apache 2.4.71, PHP 8.3.37 | builtin-phpmyadmin[technology], builtin-phpmyadmin-login[admin-panel] | Y/N/N/N/- | Y/Y/Y/Y/- |
| 6379 | Redis 7 | redis / Redis key-value store 7.4.12 | Redis 7.4.12 | - | Y/Y/Y/-/- | Y/Y/Y/-/- |
| 80 | Nginx Proxy Manager default site (openres… | http / OpenResty web app server  | - | - | Y/Y/-/-/- | Y/Y/-/-/- |
| 81 | Nginx Proxy Manager admin UI (admin) | http / OpenResty web app server  | Nginx Proxy Manager  | builtin-nginx-proxy-manager[technology], builtin-nginx-proxy-manager-ui[admin-panel] | Y/N/-/N/- | Y/Y/-/Y/- |
| 443 | Nginx Proxy Manager TLS (rejects handshak… | https / -  | - | - | Y/-/-/-/- | Y/-/-/-/- |
| 8085 | WordPress behind Traefik+Toxiproxy | http / Apache httpd 2.4.71 | WordPress 7.1.5, Apache 2.4.71, PHP 8.3.37 | builtin-wordpress-install[technology] | Y/Y/-/-/- | Y/Y/-/-/- |
| 8086 | Traefik 3.1 dashboard (admin) | http / Golang net/http server  | - | - | Y/N/N/N/- | Y/N/N/N/- |
| 8474 | Toxiproxy 2.12 API | http / Golang net/http server  | Toxiproxy 2.12.0 | builtin-toxiproxy[technology] | Y/N/N/-/- | Y/Y/Y/-/- |
| 21 | FTP vsftpd | ftp / -  | - | - | Y/N/N/-/- | Y/N/N/-/- |
| 8088 | WordPress 4.7 on old PHP (outdated) | http / Apache httpd 2.4.10 | WordPress 4.7.5, Apache 2.4.10, PHP 5.6.30 | builtin-wordpress-install[technology], outdated-wordpress[outdated], outdated-apache[outdated], outdated-php[outdated] | Y/Y/N/-/0/2 | Y/Y/Y/-/2/2 |
| 8089 | Adminer (admin) | http / -  | Adminer 6.3.0, PHP 8.4.28 | builtin-adminer[technology], builtin-adminer-login[admin-panel] | Y/N/N/N/- | Y/Y/Y/Y/- |
| 8090 | DVWA | http / Apache httpd 2.4.25 | DVWA 1.10, Apache 2.4.25, PHP  | builtin-dvwa[technology], outdated-apache[outdated] | Y/N/-/-/- | Y/Y/-/-/- |

## Run-1 defects
1. **No built-in findings (admin panels, outdated versions, notable headers/cookies)**: changed. B2c FAIL->PASS (flagged 1/1; missing: -); C2c FAIL->PASS (flagged 2/2; missing: -); C6 FAIL->FAIL (0 such findings on 6 services); D7c FAIL->FAIL (flagged 0/1; missing: 8086 findings=[]); E2c FAIL->PASS (flagged 1/1; missing: -); E4 FAIL->PASS (outdated findings: {"8088": ["Outdated WordPress 4.7.5 (WordPress 4.7.5 is older than the minimum supported 6.0 (latest 6.9))", "Outdated Apache 2.4.…); E5 FAIL->PASS (x-powered-by on 8088: 'PHP/5.6.30'; outdated findings on 8088: ['Outdated WordPress 4.7.5 (WordPress 4.7.5 is older than the minimum supported 6.0 (l…)
2. **Applications not recognised as product/technology; versions missing (WordPress 4.7)**: changed. B2b PARTIAL->PARTIAL (4/7; not recognised: 8888 (httpbin; got ''), 15432 (PostgreSQL 16; got ''), 5673 (RabbitMQ 3.x AMQP; got 'Advanced Message Queue Protocol')); C2b PARTIAL->PASS (5/5; not recognised: -); D7b PARTIAL->PARTIAL (2/3; not recognised: 8086 (Traefik 3.1 dashboard; got 'Golang net/http server')); E2b PARTIAL->PARTIAL (3/4; not recognised: 21 (FTP vsftpd; got '')); E3 FAIL->PASS (http Apache httpd 2.4.10; HTTP 200 'WordPress › Installation' server=Apache/2.4.10 (Debian); tech: WordPress 4.7.5, Apache 2.4.10, PHP 5.6.30; findin…)
3. **Service not identified: --version-light (PostgreSQL), tcpwrapped port not probed (httpbin) [filed]**: still present. B2a PARTIAL->PARTIAL (5/7; wrong: 8888=tcpwrapped, 15432=none)
4. **Traefik dual TLS/HTTP ports recorded over https, false diff changes [filed]**: changed. D8 FAIL->FAIL (scheme per run: {"d1": {"8085": "http", "8086": "https", "8474": "http"}, "d2": {"8085": "http", "8086": "https", "8474": "http"}}; 8086 in d1: https…); D3 FAIL->FAIL (service_changed 8086 [http.tls.sha256])
5. **nmap sends OPTIONS / non-HTTP probes [filed]**: still present. E7 FAIL->FAIL (methods ['GET', 'OPTIONS']; adminer: 8 requests, paths ['/', '/?CAVIT', '/api/version', '/favicon.ico', '/nice%20ports%2C/Tri%6Eity.txt%2ebak', '/ver…)
6. **top1000 misses the organisers' ports [filed]**: not re-run. 

## New in run 2
No new defect: no check that passed in run 1 fails in run 2, quickstart diffs are still exact (`service_missing 8787` / `service_returned 8787`), and every version the pack reports was checked against the images (Gitea 28.4.0, WordPress 7.1.5 and 4.7.5, phpMyAdmin 5.2.3, Adminer 6.3.0, Toxiproxy 2.12.0, DVWA 1.10). Observations:
- Still no finding of kind `interesting-header` / `interesting-cookie` on any stack (C6): `X-Powered-By: PHP/5.6.30`, phpMyAdmin and Gitea cookies are exported but not flagged. Command: `asi scan run --targets-file /work/targets.txt --ports 80,81,443,6379,8080,8081 --name c1 --max-rate 300 --wait`.
- Traefik dashboard (8086) is the one admin panel not flagged (4/5); cause is the filed https-first issue (ASI sees the TLS 404, not `/dashboard/`).
- RabbitMQ AMQP 5673 stays generic (`Advanced Message Queue Protocol`, no product/version); DVWA is a technology only (no admin/login finding, `PHP` without version).
- The pack adds `GET /version` and `GET /api/version` to every HTTP service (seen in WordPress, Adminer, DVWA logs): still GET only, requests per scan 14 -> 22 on the vulnerable stack.
- The outdated table says "latest 6.9" for WordPress while the lab's `wordpress:latest` is 7.1.5 (evidence text only; the 4.7.5 verdict is right). Bonus findings: `outdated-apache` on 8088 (2.4.10) and 8090 (2.4.25).
