# ShadowTrackr app for Splunk

Pulls data from [ShadowTrackr](https://shadowtrackr.com) (External Attack Surface
Management) into Splunk, so SOC teams can alert on it, enrich their logs with it
and explore it in dashboards.

API access requires a ShadowTrackr Business or Enterprise subscription.

## Requirements

- A ShadowTrackr Business or Enterprise subscription (for API access).
- Splunk Enterprise or Splunk Cloud Platform with the KV Store enabled. The app
  is developed and tested on Splunk Enterprise 10.2.
- Optional: CIM-compliant add-ons for your firewall, proxy, authentication and
  IDS logs (for Asset 360 and the log-based detections).
- Optional: Splunk Enterprise Security, for the correlation searches and the
  asset lookup.

## Setup

### 1. Install the app

Install it on the **search head** (Apps > Manage Apps > Install app from file).
The inputs keep their state and the inventory in the KV Store, so they run on
the search head too. In a distributed deployment, also install the app on the
instances that receive the HEC webhook (heavy forwarders or indexers), so the
`shadowtrackr:alert` events are parsed correctly. On Splunk Cloud, install it on
the search head; the webhook goes to your stack's HEC endpoint.

### 2. Create the index

Create an event index named `shadowtrackr` (Settings > Indexes). If you use
another name, update the `shadowtrackr_index` macro (Settings > Advanced search >
Search macros, app ShadowTrackr) and pick that index on the inputs.

### 3. Add your API key

In the app, open **Configuration > Accounts** and add an account with your API
key (ShadowTrackr: Settings > API access). Leave the API base URL at its
default. The key is stored encrypted in the Splunk credential store. A group
(MSSP) key collects every organization in the group.

If Splunk reaches the internet through a proxy, set it under
**Configuration > Proxy**.

### 4. Collect events

Open **Inputs > Create New Input > ShadowTrackr Events**. The defaults poll every
15 minutes and backfill 7 days on the first run.

### 5. Sync the inventory

Create a **ShadowTrackr Inventory** input. It fills the lookups that feed
`| stenrich`, the Vulnerabilities, Certificates and Asset 360 dashboards, and
several detections. By default it syncs at 07:00, 10:00, 13:00 and 16:00 on
weekdays (Splunk server time); use a cron schedule or a number of seconds to
change that.

### 6. Check that data arrives

Open the **Overview** dashboard. The **Data sources** panel at the bottom shows
when the events input, the inventory input and the webhook last delivered
data. If something stays empty, see [Troubleshooting](#troubleshooting).

### 7. Optional: receive ShadowTrackr alerts by webhook

ShadowTrackr can push the results of its alerts straight into Splunk through the
HTTP Event Collector (HEC), usually within seconds instead of the 15-minute
polling interval.

1. In Splunk, open Settings > Data inputs > **HTTP Event Collector**. Under
   *Global Settings*, set *All Tokens* to Enabled.
2. Click **New Token**. Name it e.g. `shadowtrackr_webhook`. Leave *Enable
   indexer acknowledgement* off. On the next page set the source type to
   `shadowtrackr:alert` and allow only the `shadowtrackr` index, as the default
   index. Copy the token value.
3. Test the token from a machine that can reach Splunk:

   ```sh
   curl https://<splunk>:8088/services/collector/event \
     -H "Authorization: Splunk <token>" \
     -d '{"sourcetype": "shadowtrackr:alert", "event": {"alert": "Test", "alert_id": 0,
          "delivery_id": "test-1", "result_index": 0, "result": {"asset": "www.example.com"}}}'
   ```

   Splunk answers `{"text":"Success","code":0}`, and the event shows up with
   `` `shadowtrackr_webhook_alerts` ``.
4. In ShadowTrackr, open an alert and add a webhook with the **Splunk HEC
   event** payload, the URL `https://<splunk>:8088/services/collector/event` and
   the header `Authorization: Splunk <token>`.

ShadowTrackr calls the URL from the internet, so it has to be reachable from
there over HTTPS with a certificate from a public CA. On Splunk Cloud, use
`https://http-inputs-<stack>.splunkcloud.com/services/collector/event`. On
premises, publish HEC through your reverse proxy or firewall and allow only
the `/services/collector/event` path.

Webhook retries repeat a delivery; searches deduplicate them with
`| dedup st_result_key`. When an alert has more results than fit in one
delivery, ShadowTrackr sends a marker event with `truncated=true`, which the
`shadowtrackr_webhook_alert` event type leaves out.

### 8. Turn on detections

The app ships [detections](#detections), all **disabled**. Enable the ones you
want under Settings > Searches, reports, and alerts (app ShadowTrackr, filter
`ShadowTrackr -`), then add alert actions (email, ticketing, SOAR) to them.
Fired alerts appear under Activity > Triggered Alerts. With Enterprise
Security, enable the `- Rule` versions instead (see
[Enterprise Security](#enterprise-security)).

### 9. Point the log macros at your indexes

Asset 360 and the log-based detections find your own logs through four macros
(see [Dashboards](#dashboards)). The defaults search `index=*` by CIM tag; point
them at your indexes for speed.

## Dashboards

| Dashboard | Shows |
|---|---|
| Overview | Events, problems and warnings over time; inventory counts and trends |
| Vulnerabilities & software | CVEs by severity, exploited and CISA KEV, vulnerable software, assets at risk |
| Certificates | Expiry, grades, issuers and weak configurations |
| Asset 360 | One IP, hostname or URL from every angle: ShadowTrackr's inventory, findings, CVEs, certificates, DNS and events, and your own firewall, proxy/WAF, authentication and IDS logs for the asset and its related IPs and hostnames. Click an asset in the other dashboards to open it here. |
| Search explorer | Live queries against the ShadowTrackr API with `\| shadowtrackr`, with clickable examples. Runs only when you press Submit. |

Asset 360 finds your own logs through four macros. The defaults use the CIM
tags, so they work with any CIM-compliant add-on, without accelerated data
models. For speed, point them at your indexes (Settings > Advanced search >
Search macros):

| Macro | Default |
|---|---|
| `shadowtrackr_asset_network` | `index=* tag=network tag=communicate` (firewall, network traffic) |
| `shadowtrackr_asset_web` | `index=* tag=web` (proxy, web server, WAF) |
| `shadowtrackr_asset_auth` | `index=* tag=authentication` |
| `shadowtrackr_asset_ids` | `index=* tag=ids tag=attack` (IDS/IPS, WAF attacks) |

`shadowtrackr_asset_terms("<asset>")` returns the asset with its related IPs
and hostnames, for your own searches:

```
index=firewall [| `shadowtrackr_asset_terms("www.example.com")` | rename term AS search | format]
```

## Detections

Every detection is a scheduled search that ships disabled. Each one returns
CIM-style fields (`dest`, `signature`, `severity`, ...) and is throttled, so
the same finding does not fire over and over.

| Detection | Fires when | Data | Runs | Throttle |
|---|---|---|---|---|
| Problem detected | ShadowTrackr reports a problem (level 90+) | events | every 15 min | asset + event type, 1 day |
| New known exploited vulnerability | a newly found CVE is known exploited, on the CISA KEV list or has an NCSC NL advisory | inventory | hourly | asset + CVEs, 7 days |
| Certificate expiring | a certificate expires within 14 days (`shadowtrackr_cert_expiry_days`) or expired in the last 30 days, and was not renewed | inventory | daily 07:30 | certificate, 7 days |
| Risky service exposed | a port from the `shadowtrackr_risky_ports` lookup (RDP, SMB, telnet, databases, ...) opens | events | every 15 min | asset + port, 7 days |
| Subdomain takeover risk | possible subdomain takeover, stale DNS record, or a record pointing to a domain for sale | events | every 15 min | asset + event type, 7 days |
| Asset blacklisted | one of your IPs or domains appears on a blacklist | events | every 15 min | asset, 7 days |
| Phishy domain found | a new or changed lookalike domain | events | every 15 min | domain + event type, 7 days |
| Leaked data found | your keywords, domains or emails show up in a breach, dump or on Pastebin | events | every 15 min | asset + event type, 1 day |
| Webhook alert received | a ShadowTrackr alert pushes a result through the webhook | webhook | every 15 min | result, 1 day |
| Attack on vulnerable asset | your IDS/IPS/WAF sees attacks on an asset with CVEs (high when known exploited or KEV) | your logs + inventory | hourly | asset, 1 day |
| Web traffic to phishy domain | a user or host visits a lookalike of your domains | your logs + inventory | hourly | domain, 1 day |
| External login on exposed remote access | a successful SSH/RDP/VNC/telnet/WinRM login from an internet address on an asset where ShadowTrackr sees that service exposed | your logs + inventory | hourly | asset + user + source, 1 day |

Notes:

- Searches over the events feed use index time, so events that arrive late are
  not missed. Events older than 7 days never fire, so the first-run backfill
  does not flood the alert queue.
- Inventory detections treat the first inventory sync as the baseline: only
  findings that appear after it fire.
- To change the risky ports, upload your own CSV with the columns `port`,
  `service` and `reason` (Settings > Lookups > Lookup table files), then point
  the `shadowtrackr_risky_ports` lookup definition at it. Edits to the CSV that
  ships with the app are lost on upgrade.

Three health checks watch the app itself:

| Health check | Fires when |
|---|---|
| Health - No events received | the events input indexed nothing for 24 hours |
| Health - Input errors | the inputs logged errors in the last hour (needs access to `index=_internal`) |
| Health - Inventory stale | an inventory type failed on its last sync, or did not sync for 4 days |

## Enterprise Security

Each detection also ships as an ES correlation search named
`ShadowTrackr - <detection> - Rule`, disabled. They create:

- a **notable event**, with a drilldown to the underlying ShadowTrackr data, and
- **risk events**: the asset (`dest`) as a system risk object, users and
  sources where the detection has them, CVEs, domains and attacker IPs as
  threat objects,
- with **MITRE ATT&CK** annotations where a technique fits (T1190, T1133,
  T1078, T1566, T1583.001, T1584.001, T1589.001).

In ES, open Content Management, filter on `ShadowTrackr`, and enable the
`- Rule` searches you want. Do not also enable the plain version of the same
detection, or every finding fires twice.

**Assets.** The `ShadowTrackr - ES asset lookup - Lookup Gen` search (disabled,
daily at 17:15) writes every internet-facing host and website from the
inventory to the `shadowtrackr_es_assets` lookup, in the ES asset format. The
priority is *critical* for a CVE on the CISA KEV list or a ShadowTrackr problem,
*high* for other CVEs, *medium* for warnings, and *low* otherwise. The category
is `shadowtrackr|internet_facing`. To use it:

1. Enable the search and run it once.
2. In ES, open the Asset and Identity Management configuration and add a new
   asset lookup with the lookup `shadowtrackr_es_assets`.

An app upgrade resets the lookup to empty until the search runs again.

## What gets collected

| Input | Sourcetype | Notes |
|---|---|---|
| ShadowTrackr Events | `shadowtrackr:events` | Polls `/events` with `since_id` paging (every 15 minutes by default) and keeps its checkpoint in the KV Store. The first run backfills the configured number of days. It never uses `update_only`, so other API consumers are not affected. |
| ShadowTrackr Inventory | KV Store lookups + `shadowtrackr:inventory:summary` | Syncs the inventory every 3 hours during office hours (07:00, 10:00, 13:00 and 16:00 on weekdays, in the Splunk server's time zone; change the cron schedule or use seconds on the input) into one lookup per type (`shadowtrackr_hosts`, `shadowtrackr_websites`, `shadowtrackr_urls`, `shadowtrackr_domains`, `shadowtrackr_subnets`, `shadowtrackr_certificates`, `shadowtrackr_dns`, `shadowtrackr_mailservers`, `shadowtrackr_software`, `shadowtrackr_cves`, `shadowtrackr_cloud_providers`, `shadowtrackr_remote_login_services`, `shadowtrackr_blacklisted_assets`, `shadowtrackr_exposed_emails`, `shadowtrackr_suggestions`, `shadowtrackr_phishy_domains`, `shadowtrackr_suppliers`, `shadowtrackr_internet_standards`). Each row has `st_first_synced`, `st_last_synced` and `st_present`; rows ShadowTrackr no longer reports stay for 30 days with `st_present=0`. Per-run counts go to the index for trends. |
| Alert webhook (HEC) | `shadowtrackr:alert` | Results of ShadowTrackr alerts, pushed by ShadowTrackr to HEC. See [step 7](#7-optional-receive-shadowtrackr-alerts-by-webhook). The index comes from the HEC token. |

Searches use these macros, so the index is set in one place:

| Macro | Expands to |
|---|---|
| `shadowtrackr_index` | `index=shadowtrackr` |
| `shadowtrackr_events` | the events feed |
| `shadowtrackr_webhook_alerts` | alert results pushed by webhook |
| `shadowtrackr_inventory_summary` | per-run inventory counts |

The lookups also work directly, e.g.
`index=firewall | lookup shadowtrackr_hosts ip AS dest_ip OUTPUT services vulnerable problems`.

## Search commands

### `| stenrich`: add ShadowTrackr context to any search

```
index=firewall action=allowed | stenrich field=dest_ip | where st_known=1 AND st_vulnerable=1
index=proxy | stenrich field=url | where st_phishy=1
```

`stenrich field=<field> [type=auto|ip|domain] [prefix=st_]` looks up IPs,
hostnames and URLs (URLs, `host:port` and `user@host` are reduced to the host)
in the inventory lookups and adds:

| Field | Meaning |
|---|---|
| `st_known` | 1 if ShadowTrackr knows this asset (host, website, certificate, DNS name or URL) |
| `st_in_scope` | 1 if known, or a subdomain of one of your domains that ShadowTrackr has not found (yet) |
| `st_asset_type` | host, website, certificate, hostname, url |
| `st_organization` | organization (group keys) |
| `st_ip`, `st_hostnames`, `st_domain` | IPs a name resolves to, names on an IP, your parent domain |
| `st_ports`, `st_services`, `st_software` | open TCP ports, services, detected software |
| `st_country`, `st_asn_name`, `st_cloud_provider` | location and network |
| `st_problem`, `st_warning`, `st_problems`, `st_warnings`, `st_tags` | ShadowTrackr findings |
| `st_vulnerable`, `st_cves`, `st_cve_count`, `st_max_cvss`, `st_exploited`, `st_cisa_kev` | CVEs on this asset |
| `st_web_grade`, `st_cert_grade`, `st_cert_expires`, `st_cert_issuer` | website and certificate (worst grade, soonest expiry) |
| `st_phishy`, `st_lookalike_of`, `st_phishy_score` | the name is (a subdomain of) a phishy lookalike domain |
| `st_first_seen`, `st_last_seen` | when ShadowTrackr first and last saw it |

It makes no API calls: the data comes from the ShadowTrackr Inventory input,
so any role that can read the app's lookups can use it. Each distinct value
is looked up once per search, and lookups are batched, so it is fine on large
searches. It runs on the search head.

### `| shadowtrackr`: live queries

```
| shadowtrackr query="index=hosts problem=yes"
| shadowtrackr query="index=certificates by issuer earliest=-7d"
| shadowtrackr query="index=events earliest=-1d level>=80" | stats count by source
```

`shadowtrackr query="<query>" [account=<name>] [max_results=10000]` runs a
query in the ShadowTrackr search language (the same as the search box in
ShadowTrackr, see the [search docs](https://www.shadowtrackr.com/docs_v3/3-Search-and-Queries))
against the API and returns the rows. Comma-separated lists such as
`tcp_ports` and `software` become multivalue fields and booleans become 1/0.
Without `account=` the only configured account is used. The **Search
explorer** dashboard is a front end for it.

The command reads the encrypted API key, which in Splunk needs the
`list_storage_passwords` capability. Admins have it. The app deliberately
does not grant it to other roles, because that capability exposes every
stored secret in Splunk; other users get a clear error and can still use
`stenrich`, the lookups and the dashboards.

### CIM mapping

| Event type | Tags | Contents |
|---|---|---|
| `shadowtrackr_alert` | `alert` | ShadowTrackr problems, level 90+ |
| `shadowtrackr_warning` | `alert` (disabled) | Warnings, level 80-89. Enable the tag under Settings > Tags to treat warnings as alerts too. |
| `shadowtrackr_change` | `change` | Changes to assets |
| `shadowtrackr_vulnerability` | `vulnerability`, `report` | CISA KEV, NCSC advisories, subdomain takeover, ... |
| `shadowtrackr_webhook_alert` | `alert` | Results of ShadowTrackr alerts pushed by webhook |

Event types are classified by the catalogue from the API's `/event_types`
(refreshed daily into the KV Store). `shadowtrackr_event_type_overrides.csv`
corrects the CIM type for a few event types.

## Permissions

- Users need read access to the `shadowtrackr` index for the dashboards and
  searches.
- `| stenrich`, the lookups and the dashboards need no special capability.
- `| shadowtrackr` (and the Search explorer) reads the encrypted API key, which
  needs `list_storage_passwords`; see [above](#-shadowtrackr-live-queries).
- The detections run as scheduled searches owned by `nobody`. The health check
  for input errors reads `index=_internal`.

## Troubleshooting

| Symptom | Check |
|---|---|
| No events | Run `index=_internal source=*shadowtrackr_*.log*`. The input logs every run and every API error there. For more detail, set the log level to DEBUG under Configuration > Logging. |
| "Invalid API key" or "no API access" in the log | Copy the key again from ShadowTrackr: Settings > API access. API access needs a Business or Enterprise subscription. |
| Connection errors | Splunk cannot reach `api.shadowtrackr.com`; set the proxy under Configuration > Proxy. |
| Events in another index than the dashboards search | The `shadowtrackr_index` macro must match the input's index. |
| Vulnerabilities, Certificates or Asset 360 empty | Create the Inventory input and wait for its first run (or lower the interval once). Check that the KV Store is up: run `\| rest /services/kvstore/status`. |
| `stenrich` warns "Lookup ... not found" | The Inventory input has not run yet. |
| Webhook events do not arrive | Run `curl https://<splunk>:8088/services/collector/health`, then the test in step 7. Check that the token allows the `shadowtrackr` index. HEC errors show up in `index=_internal sourcetype=splunkd component=HttpInputDataHandler`. |
| A detection never fires | Run its search by hand over a longer time range. The log-based detections need the four log macros to find your data, and the inventory detections need the Inventory input. |

## Development

Requirements: Python 3.9+, Docker, `libmagic` (for AppInspect, `brew install libmagic`).

```sh
python3 -m venv venv && . venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env          # set SPLUNK_PASSWORD etc.

make up                       # start Splunk in Docker (http://localhost:8000)
make index                    # create the shadowtrackr index
make deploy                   # build and copy the app; keeps local/ config
make restart                  # deploy and restart Splunk
make test                     # pytest
make test-bundled             # pytest against the libraries bundled in the app
make inspect                  # AppInspect with the cloud tag
make dashboards               # regenerate the dashboards
make savedsearches            # regenerate the detections
make hec                      # send synthetic webhook deliveries through HEC and check the parsing
```

### Mock API

`make mock` serves the redacted fixtures in `tests/fixtures/` on port 8081, with
timestamps shifted to the present. Add an account in Splunk with:

- API base URL: `http://host.docker.internal:8081/api/v4`
- API key: `mock-api-key-0000000000`, or `mock-group-key-000000000` for a group
  (MSSP) key with two organizations

The mock implements the v4 API (since_id paging, structured fields,
`/event_types`, status codes, group keys). `python3 mock_api/server.py --legacy`
behaves like the API before those changes. Fault injection keys:
`mock-error-500`, `mock-error-429`, `mock-error-slow`, `mock-error-html` and
`mock-no-api-access`. `POST /_mock/insert` adds an event, e.g. a late insert.

### Dev logs for Asset 360

`make devlogs` creates a `devlogs` index with CIM eventtypes and tags in the dev
Splunk and sends a week of synthetic firewall, proxy/WAF, authentication and IDS
events (via HEC) for a few assets from the `shadowtrackr_hosts` lookup, so the
log panels of Asset 360 have data. Run the inventory input first.

### Webhook

`make hec` posts the synthetic deliveries in `tests/fixtures/webhook_alerts.json`
(including a retry and a truncation marker) to the dev Splunk's HEC with
`SPLUNK_HEC_TOKEN`, into the `shadowtrackr` index, then checks `dest`,
`severity`, `vendor_account`, the retry dedupe and the event type. The alerts
are named `TEST - ...`.

### Fixtures

Never commit raw API responses. Use `tools/redact_events.py` to turn a raw
response into a fixture, then review the result before committing. The v4 fields
in the current fixtures are synthetic (`tools/add_v4_fields.py`) and should be
replaced by redacted live responses.

The dashboards are generated by `tools/gen_dashboards.py` and the detections
(`savedsearches.conf`, plain and ES versions from one definition) by
`tools/gen_savedsearches.py`; edit the generators, not the output. The app
icons, app-bar logo and dashboard logo tile are generated from
`assets/brand/shadowtrackr-logo.png` by `tools/gen_brand_assets.py` (needs Pillow
and macOS's Avenir Next font for the wordmark).

## License

Apache-2.0
