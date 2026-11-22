# Vulhub holdout: products the signature pack was NOT written for

Lab `asi-vulhub-holdout` (172.28.33.0/24, internal, no published ports); truth `eval/vulhub/truth-holdout.json`;
run `LAB=holdout eval/vulhub/run.sh`; raw results in `eval/results/vulhub/holdout/`. One run on main, 2026-11-21.

## Products (11 services, 33 truth ports)
| Addr | Product | Version | Verified by running |
|---|---|---|---|
| .10 | Apache Solr | 8.2.0 | /solr/admin/info/system |
| .11 | Apache CouchDB | 2.1.0 | Server header, JSON at / |
| .12 | Nacos | 1.4.0 | /nacos/v1/console/server/state (root is a bare 404) |
| .13 | Metabase | 0.40.4 | /api/session/properties |
| .14 | Webmin | 1.910 | Server: MiniServ/1.910 (HTTPS) |
| .15 | GlassFish | 4.1 | Server header |
| .16 | InfluxDB | 1.6.6 | X-Influxdb-Version header |
| .17 | OpenSMTPD | 6.6.1p1 | image tag only |
| .18 | Gogs | 0.11.66 | httpx saw 0.11.66.0916; not installed (/install) |
| .19 | Openfire | 4.7.4 | /login.jsp |
| .20 | Mosquitto | 1.6.15 | start-up log; NOT Vulhub (official image), never-probe target |
## Scores (same score.py, same truth; all tools found 11/11 hosts except httpx, which only gets HTTP URLs)
| Tool | Recognised | Version exact | Admin flagged (of 5) | False technologies |
|---|---|---|---|---|
| nmap -sV --version-light | 6/11 | 4/11 | 0 | 0 |
| nmap -sV (default) | 7/11 | 4/11 (+1 wrong) | 0 | 0 |
| httpx -td | 4/11 | 2/11 (+1 major.minor) | 0 | 6 |
| ASI (main) | 6/11 | 3/11 (+1 wrong) | 1 (+1 false flag) | 0 |

Same rules for every tool: "Jetty", "Golang net/http server", "Apache Tomcat", "Java" do not count as Metabase,
Openfire, InfluxDB, Gogs or Nacos; "MiniServ" counts as Webmin; Openfire "3.10.0 or later" is scored as wrong.
httpx's 6 "false" technologies are real libraries missing from the ignore list (Solr UI's D3 etc.), no wrong product.
## What ASI reported per product
| Product | ASI result | Source |
|---|---|---|
| Solr | recognised "Apache Solr", no version; admin UI at / not flagged | nmap product string |
| CouchDB | "CouchDB httpd" 2.1.0 exact | nmap product string |
| Nacos | NOT recognised ("Apache Tomcat", title "HTTP Status 404") | - |
| Metabase | NOT recognised (product "Jetty 9.4.32"; http.title was "Metabase" but nothing used it) | - |
| Webmin | "MiniServ" 1.910 exact; login page not flagged as admin panel | nmap product string |
| GlassFish | "Oracle GlassFish" 4.1 exact; admin-panel flagged on 4848 by the generic login-form rule | nmap product string |
| InfluxDB | NOT recognised ("Golang net/http server"); stock nmap named it with 1.6.6 | - |
| OpenSMTPD | recognised, no version | nmap product string |
| Gogs | NOT recognised (title "Installation - Gogs" unused); admin-panel flagged on the install page (false by truth) | - |
| Openfire | recognised on XMPP ports, version "3.10.0 or later"; admin console on 9090 not flagged | nmap product string |
| Mosquitto | port 1883 open, service "mqtt", no product | - |
## Signatures versus nmap
All 6 ASI recognitions come from `services[].product` (the nmap product string); none from ASI signatures.
`technologies[]` held only Java and OpenSSH 7.7 (both `builtin`); no `signature:<id>` source appears in the export.
Findings were generic: version-disclosing headers, a stack cookie, login form (2), and one `outdated` - for OpenSSH
on the Gogs host, not for a holdout product (0/11). Against stock nmap light ASI lost InfluxDB and gained Openfire.
## What the MQTT target logged (`holdout/mqtt-log-full.txt`, mosquitto with `log_type all`)
- ASI (172.28.33.2): one connection; after 6 s idle a valid MQTT CONNECT as client id `nmap`, CONNACK, disconnect.
  No rejected connection, so no HTTP reached the broker - but it is still nmap's MQTT version probe, not silence.
- nmap light: a connect-scan connection plus the same CONNECT. nmap default: also `mqtt-subscribe` on `#` and
  `$SYS/#`, reading about 70 messages. Limit: mosquitto logs events, not bytes; "no HTTP" is inferred.
## Conclusion
On the 16 prepared products ASI scores 16/16 recognised and 14/16 exact versions against nmap's 10/16 and 8/16.
On 11 products it was not prepared for, ASI is level with nmap light (6/11) and below default nmap (7/11), with
one fewer exact version (3 versus 4). The advantage does not carry over: off the pack, ASI is its embedded nmap
plus generic findings. What does hold is 0 false technologies and safer behaviour on MQTT than default nmap.
Cheap wins visible in the data: use http.title and version headers (Metabase, Gogs, Solr Admin, X-Influxdb-Version).
