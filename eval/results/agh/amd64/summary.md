# amd64 check on gruz (NixOS x86_64, rootless podman 5.8.9) - 2026-11-21
Commit: 983887d9842283e663a6dbbd3b41cead780fd6fa (main, snapshot worktree). Image built on the Mac with
`docker buildx build --platform linux/amd64 -t asi:amd64 --load /tmp/claude-502/amd64snap`, moved with
`docker save asi:amd64 | ssh dazak@gruz.local podman load`. Exact scripts: raw/ftp.sh, raw/ftp2.sh, raw/web.sh.
## Setup (no published ports; `podman network create --internal asi-ftp-net`)
- asi-ftp-pg: postgres:17-alpine; asi-ftp-asi: asi:amd64, `--entrypoint sleep ... infinity`, `--cap-add NET_RAW`
- asi-ftp-vsftpd: fauria/vsftpd, FTP_USER=test FTP_PASS=test123 PASV_MIN_PORT=21000 PASV_MAX_PORT=21010
  (PASV_ADDRESS left unset - differs from the organisers' 127.0.0.1, irrelevant without a login)
- asi-ftp-vsftpd-proto: same image/env plus `log_ftp_protocol=YES` appended to vsftpd.conf (evidence only)
- `asi migrate`; `asi scan run --targets-file F --ports 21,21000-21010 --name ftp-1|ftp-2 --max-rate 300 --wait`;
  `asi export --format json --out F --run NAME`; `asi diff --from ftp-1 --to ftp-2 --format json --out F`
## FTP: nmap baseline versus ASI (port 21)
| Tool | service | product | version |
|---|---|---|---|
| `nmap -sT -sV --version-light -p 21` (7.97) | ftp | vsftpd | 3.0.2 |
| `nmap -sT -sV -p 21` | ftp | vsftpd | 3.0.2 |
| ASI ftp-1 / ftp-2 | ftp | vsftpd | 3.0.2 |
ASI technologies: vsftpd 3.0.2 (category ftp-server, confidence 80, source builtin). Findings: none - there is
NO `outdated` finding for vsftpd 3.0.2 (released 2012). interest_score 10. `http: null`.
Ports 21000-21010: closed (no passive listener without a logged-in session; `nmap --version-all` agrees) and
not recorded at all - the export has only the port 21 service. Diff ftp-1 -> ftp-2: `"changes": []`.
## FTP safety observations
- Organiser-config container, /var/log/vsftpd.log after 2x nmap + 2x ASI: exactly 4 `CONNECT: Client` lines,
  nothing else. /var/log/vsftpd/vsftpd.log (xferlog) was never created; `podman logs` has only the start banner.
- Protocol-logging container, after one ASI scan: one `CONNECT` and one `FTP response ... "220 (vsFTPd 3.0.2)"`.
  No `FTP command` line at all: no USER, no PASS, no HTTP request text, no login attempt. One connection per scan.
- nmap light/default/--version-all add the same CONNECT + 220 pair each, also without commands.
- Passive ports were closed, so "HTTP against an open passive port" could not be exercised.
## Rest of the stack (ports 80,8080; runs web-1, web-2)
| Container | ASI result | Findings by kind |
|---|---|---|
| wordpress:4.7 (:80) | Apache httpd 2.4.10; WordPress 4.7.5, Apache 2.4.10, PHP 5.6.30; title "WordPress > Installation" | outdated x3 (WordPress 4.7.5 < 6.0, Apache < 2.4.52, PHP 5.6.30 < 8.1); interesting-header x2 (X-Powered-By, Server); admin-panel (login form /wp-admin/install.php); technology |
| adminer (:8080) | product/version empty at service level; Adminer 6.3.0, PHP 8.4.28 | admin-panel (Adminer login); interesting-header (X-Powered-By); technology; no outdated |
| vulnerables/web-dvwa (:80) | Apache httpd 2.4.25; DVWA 1.10, Apache 2.4.25, PHP (no version: no X-Powered-By) | outdated (Apache); interesting-header (Server); interesting-cookie x2 (PHPSESSID stack, no HttpOnly); admin-panel (login form /login.php); technology |
mysql:5.7 was not scanned (3306 not in the port list). Closed ports (8080 on wordpress/dvwa, 80 on adminer) are not recorded.
Diff web-1 -> web-2 is NOT empty: 1 `service_changed` on adminer:8080 - `http.headers.content-security-policy`
(per-request nonce) and `http.favicon_sha256` differ between runs. False change on every run; needs a ticket.
Requests seen in access logs (both runs together):
- ASI client `asi-discovery/0.0.0-dev`, GET only: `/`, `/favicon.ico`, `/version`, `/api/version`, and followed
  redirects `/wp-admin/install.php` (3 per run) and `/login.php`. No HEAD, no POST, nothing else.
- nmap probes (listed separately): `GET /` with empty User-Agent, once per run per Apache host; on adminer
  (php -S logs no User-Agent) 2 of the 4 `GET /` plus one "Invalid request (Connection reset by peer)" per run.
  No OPTIONS was seen at this probe intensity.
## Not done / problems
- First attempt lost the containers: they received SIGTERM when the SSH session ended (no lingering for the
  user); fixed by holding one SSH session open, not by `loginctl enable-linger`.
- `localhost/asi:amd64` does not exist after `podman load`; the image name is `docker.io/library/asi:amd64`.
- adminer's access log has no User-Agent, so the ASI/nmap split there is inferred from counts.
- Cleanup: all asi-ftp-* containers, asi-ftp-net, 7 anonymous volumes, the 7 pulled/loaded images and
  ~/asi-ftp-test removed; image list equals the one recorded before (gruz-before.txt / gruz-after.txt).
