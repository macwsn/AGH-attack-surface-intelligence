# Holdout 3 (unseen, 8 web applications) - AFTER the metadata/title rule

ASI built once from `git archive b42874d`. One run, 2026-11-22. nmap baselines are those of the BEFORE run (bbe6ac5 day).
Raw output is kept outside the repository; this file holds scores only (technology names as reported, no page content).

| Tool | Recognised | Version right | False technologies | Admin flagged (of 3) | Wall-clock |
|---|---|---|---|---|---|
| ASI b42874d (after) | 3/8 | 1/8 | 1 | 2 (+2 not in truth) | 106 s |
| ASI bbe6ac5 (before) | 1/8 | 1/8 | 0 | 2 (+2 not in truth) | 107 s |
| nmap -sV --version-light | 1/8 | 1/8 | 0 | 0 | 28 s |
| nmap -sV default | 1/8 | 1/8 | 0 | 0 | 29 s |

| Product (truth version) | ASI recognised | Source | Version | Admin flagged / expected | False technologies |
|---|---|---|---|---|---|
| Syncthing 1.27.4 | yes | nmap + heuristic (header) | right | yes / yes | none |
| Etherpad 1.9.7 | NO | - | - | no / no | none |
| File Browser 2.27.0 | NO | - | - | no / yes | "assets" (heuristic, app-metadata rule, confidence 40) |
| Meilisearch 1.7.3 | NO | - | - | yes / no | none |
| Kanboard 1.2.35 | NO | - | - | yes / no | none |
| Navidrome 0.51.1 | yes (new) | heuristic (app-metadata) | none | no / no | none |
| ntfy 2.9.0 | yes (new) | heuristic (app-metadata), reported as "ntfy web" | none | no / no | none |
| AdGuard Home 0.107.45 | NO | - | - | yes / yes | none |

- The new rule added 2 recognitions (Navidrome, ntfy), no versions, and 1 false technology: "assets" on File Browser is
  not a product; the rule took a non-product string for the application name.
- "ntfy web" is counted as ntfy (alias matched as a whole word); the name is not the clean product name.
- The corroborated-title branch of the rule did not fire on this set; both gains are from application metadata.
- All 8 hosts and 10/10 ports found. Admin flags unchanged from BEFORE.
