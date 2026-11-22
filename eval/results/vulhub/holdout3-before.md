# Holdout 3 (unseen, 8 web applications) - BEFORE the metadata/title rule

ASI built once from `git archive bbe6ac5`. One run, 2026-11-22. Same /24 and truth ports for all tools.
Raw output (exports, nmap XML) is kept outside the repository on purpose; this file holds scores only.

| Tool | Recognised | Version right | False technologies | Admin flagged (of 3) | Wall-clock |
|---|---|---|---|---|---|
| ASI bbe6ac5 | 1/8 | 1/8 | 0 | 2 (+2 not in truth) | 107 s |
| nmap -sV --version-light | 1/8 | 1/8 | 0 | 0 | 28 s |
| nmap -sV default | 1/8 | 1/8 | 0 | 0 | 29 s |

| Product (truth version) | ASI recognised | Source | Version | Admin flagged / expected |
|---|---|---|---|---|
| Syncthing 1.27.4 | yes | nmap + heuristic (header) | right | yes / yes |
| Etherpad 1.9.7 | NO | - | - | no / no |
| File Browser 2.27.0 | NO | - | - | no / yes |
| Meilisearch 1.7.3 | NO | - | - | yes / no |
| Kanboard 1.2.35 | NO | - | - | yes / no |
| Navidrome 0.51.1 | NO | - | - | no / no |
| ntfy 2.9.0 | NO | - | - | no / no |
| AdGuard Home 0.107.45 | NO | - | - | yes / yes |

All 8 hosts and 10/10 ports found by every tool. nmap (both intensities) recognised Syncthing only.
Wall-clock: ASI at `--max-rate 300`, nmap unthrottled. Admin truth is a judgement call (see truth-holdout3.json).
