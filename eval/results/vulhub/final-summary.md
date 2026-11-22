# Final round: ASI at c9403c2 versus nmap -sV

ASI image built once from `git archive c9403c2`. Same targets (/24) and same truth ports for all three tools; one lab up at a time.
Raw exports, nmap XML and scores: `eval/results/vulhub/final-c9403c2/<set>/`. One run per set, 2026-11-22.
Strict scoring: a web server, language or framework is not the product. Version "right" = exact string; a build suffix is shown separately.
False technology = a product named that is not there (reviewed by hand; real JS libraries and frameworks are not counted).
Wall-clock: ASI is the `scan run` step at `--max-rate 300`; nmap ran unthrottled, so times are not like for like.

## Holdout 2 - UNSEEN (12 products, 21 ports) - the number that matters
| Tool | Recognised | Version right | False technologies | Admin flagged | Wall-clock |
|---|---|---|---|---|---|
| ASI c9403c2 | 4/12 | 2/12, 1 wrong | 0 | 2/7 (+1 not in truth) | 253 s |
| nmap -sV --version-light | 3/12 | 1/12, 1 wrong | 0 | 0/7 | 34 s |
| nmap -sV default | 3/12 | 1/12, 1 wrong | 0 | 0/7 | 94 s |

| Product (truth version) | ASI recognised | Source | Version | Admin flagged / expected | False technologies |
|---|---|---|---|---|---|
| Uptime Kuma 1.23.13 | NO | - | - | yes / yes | none |
| HashiCorp Vault 1.15.6 | NO | - | - | no / yes | none |
| HashiCorp Consul 1.17.3 | NO | - | - | no / yes | none |
| pgAdmin 8.4 | NO | - | - | yes / yes | none |
| Matomo 5.0.3 | yes | heuristic | right | yes / no | none |
| Gotify 2.4.0 | yes | nmap | none | no / yes | none |
| Node-RED 3.1.9 | NO | - | - | no / yes | none |
| Mailpit 1.15.1 | NO | - | - | no / yes | none |
| NATS 2.10.12 | NO | - | - | no / no | none |
| Apache ZooKeeper 3.9.2 | NO | - | - | no / no | none |
| Memcached 1.6.24 | yes | nmap | right | no / no | none |
| MongoDB 6.0.14 | yes | nmap | wrong (6.1 or later) | no / no | none |

## Holdout 1 - seen by the detection task as fixtures (11 products, 33 ports)
| Tool | Recognised | Version right | False technologies | Admin flagged | Wall-clock |
|---|---|---|---|---|---|
| ASI c9403c2 | 9/11 | 4/11 (+1 with build suffix), 1 wrong | 0 | 3/5 (+1 not in truth) | 280 s |
| nmap -sV --version-light | 6/11 | 4/11, 0 wrong | 0 | 0/5 | 35 s |
| nmap -sV default | 7/11 | 4/11, 1 wrong | 0 | 0/5 | 196 s |

| Product (truth version) | ASI recognised | Source | Version | Admin flagged / expected | False technologies |
|---|---|---|---|---|---|
| Apache Solr 8.2.0 | yes | heuristic+nmap | none | yes / yes | none |
| Apache CouchDB 2.1.0 | yes | nmap+wappalyzer | right | no / no | none |
| Nacos 1.4.0 | NO | - | - | no / no | none |
| Metabase 0.40.4 | yes | heuristic | none | yes / yes | none |
| Webmin 1.910 | yes | nmap+wappalyzer | right | no / yes | none |
| GlassFish 4.1 | yes | nmap+wappalyzer | right | yes / yes | none |
| InfluxDB 1.6.6 | yes | heuristic+nmap | right | no / no | none |
| OpenSMTPD 6.6.1p1 | yes | nmap | none | no / no | none |
| Gogs 0.11.66 | yes | wappalyzer | right + build suffix (0.11.66.0916) | yes / no | none |
| Openfire 4.7.4 | yes | nmap | wrong (3.10.0 or later) | no / yes | none |
| Mosquitto 1.6.15 | NO | - | - | no / no | none |

## Vulhub lab - products the pack was written for (16 services, 27 ports)
| Tool | Recognised | Version right | False technologies | Admin flagged | Wall-clock |
|---|---|---|---|---|---|
| ASI c9403c2 | 16/16 | 15/16, 0 wrong | 1 | 4/4 (+4 not in truth) | 267 s |
| nmap -sV --version-light | 10/16 | 8/16, 1 wrong | 0 | 0/4 | 34 s |
| nmap -sV default | 10/16 | 8/16, 1 wrong | 0 | 0/4 | 165 s |

| Product (truth version) | ASI recognised | Source | Version | Admin flagged / expected | False technologies |
|---|---|---|---|---|---|
| Joomla 4.2.7 | yes | builtin | none | yes / no | none |
| Drupal 8.5.0 | yes | builtin | right | yes / no | none |
| WordPress 4.6 | yes | signature | right | yes / no | bun |
| Apache Tomcat 8.0.43 | yes | nmap+signature | right | no / no | none |
| Jenkins 2.441 | yes | signature | right | yes / yes | none |
| Grafana 8.2.6 | yes | nmap+signature | right | yes / yes | none |
| phpMyAdmin 4.8.1 | yes | signature | right | yes / yes | none |
| nginx 1.13.2 | yes | builtin+nmap | right | no / no | none |
| Apache HTTP Server 2.4.49 | yes | builtin+nmap | right | no / no | none |
| Elasticsearch 1.4.2 | yes | nmap+signature | right | no / no | none |
| Redis 4.0.14 | yes | builtin+nmap | right | no / no | none |
| Apache ActiveMQ 5.17.3 | yes | builtin+nmap+signature | right | yes / yes | none |
| Gitea 1.4.0 | yes | signature | right | yes / no | none |
| MySQL 5.7.44 | yes | builtin+nmap | right | no / no | none |
| MySQL 5.7.44 | yes | builtin+nmap | right | no / no | none |
| MySQL 5.5.62 | yes | builtin+nmap | right | no / no | none |
## Notes
- Holdout 2 misses: ASI's own `http.title` held "Uptime Kuma", "Vault", "Consul by HashiCorp", "pgAdmin 4", "Node-RED" and
  "Mailpit", yet none became a technology; the title heuristic fired only for Matomo (title with a version). NATS and
  ZooKeeper were missed by all tools. MongoDB "6.1 or later" (ASI and nmap) is wrong for 6.0.14.
- Holdout 1 moved from 6/11 (run on 2026-11-21, before the detection task) to 9/11; that gain was built on these fixtures.
- Admin flags "not in truth": install wizards (Matomo, Gogs, Drupal, WordPress, Gitea) and Joomla's login form. Truth says
  the root is not an admin panel there; calling an unfinished installation a finding is defensible.
- Only real false technology in three sets: "bun" on WordPress 4.6 (wappalyzer source). Not counted as false, after review:
  Chosen, D3, Highlight.js, timeago (Solr UI), JavaServer Pages (GlassFish), Macaron (Gogs).
- MQTT (holdout 1, Mosquitto log): no connection at all from the ASI scanner this time (finding "Not probed by policy");
  the earlier build still sent nmap's MQTT CONNECT. Both nmap baselines connected, default also subscribed to `#`.
- Admin truth and the false-technology review are one person's judgement; single run per set, no variance estimate.

## Conclusion
On products it has never seen ASI recognises 4/12 with 2 right versions, against 3/12 and 1 for nmap: a margin of one product (Matomo).
The large leads (16/16 vs 10/16 on the lab, 9/11 vs 6-7/11 on holdout 1) are on sets the pack or the fixtures were built from.
What generalises is precision (1 false technology in 39 services) and admin/install flags; breadth of recognition does not yet.

## Addendum: general metadata/title rule (b42874d), ASI only
| Set | ASI before | ASI after b42874d | nmap light / default | False technologies after |
|---|---|---|---|---|
| Holdout 3 - UNSEEN (8 web apps) | 1/8, 1 version (bbe6ac5) | 3/8, 1 version | 1/8 / 1/8 | 1: "assets" on File Browser |
| Holdout 2 - DEVELOPMENT SET, used to design the rule (12) | 4/12, 2 versions (c9403c2) | 7/12, 2 versions | 3/12 / 3/12 | 0 |

- Holdout 3 after: new Navidrome and ntfy (as "ntfy web"), both from application metadata, no version. Still missed:
  Etherpad, File Browser, Meilisearch, Kanboard, AdGuard Home. Details: `holdout3-before.md`, `holdout3-after.md`.
- Holdout 2 after: new Vault, Consul, Node-RED (corroborated title, confidence 30); Gotify now also from metadata.
  Still missed: Uptime Kuma, pgAdmin, Mailpit, NATS, ZooKeeper. This set shaped the rule, so 7/12 is not a generalisation number.
- Honest reading: on unseen products the rule lifts ASI from parity with nmap (1/8) to 3/8, gives no versions, and
  produced one false technology in 8 services. One run per set.
