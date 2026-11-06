# ShadowTrackr app for Splunk

Pulls data from [ShadowTrackr](https://shadowtrackr.com) (External Attack Surface
Management) into Splunk, so SOC teams can alert on it, enrich their logs with it
and explore it in dashboards.

API access requires a ShadowTrackr Business or Enterprise subscription.

> Work in progress. A full setup guide follows in a later release.

## Quick start

1. Create an index named `shadowtrackr` (Settings > Indexes). If you use another
   index, update the `shadowtrackr_index` macro.
2. In the app, open **Configuration > Accounts** and add your API key
   (ShadowTrackr: Settings > API access). The key is stored encrypted in the
   Splunk credential store.
3. Open **Inputs** and create a **ShadowTrackr Events** input.
4. Optionally create a **ShadowTrackr Inventory** input for the lookups and the
   Vulnerabilities and Certificates dashboards.
5. Open the **Overview** dashboard.

## What gets collected

| Input | Sourcetype | Notes |
|---|---|---|
| ShadowTrackr Events | `shadowtrackr:events` | Polls `/events` with `since_id` paging (every 15 minutes by default) and keeps its checkpoint in the KV Store. The first run backfills the configured number of days. It never uses `update_only`, so other API consumers are not affected. |
| ShadowTrackr Inventory | KV Store lookups + `shadowtrackr:inventory:summary` | Syncs the inventory every 3 hours during office hours (07:00, 10:00, 13:00 and 16:00 on weekdays, in the Splunk server's time zone; change the cron schedule or use seconds on the input) into one lookup per type (`shadowtrackr_hosts`, `shadowtrackr_websites`, `shadowtrackr_urls`, `shadowtrackr_domains`, `shadowtrackr_subnets`, `shadowtrackr_certificates`, `shadowtrackr_dns`, `shadowtrackr_mailservers`, `shadowtrackr_software`, `shadowtrackr_cves`, `shadowtrackr_cloud_providers`, `shadowtrackr_remote_login_services`, `shadowtrackr_blacklisted_assets`, `shadowtrackr_exposed_emails`, `shadowtrackr_suggestions`, `shadowtrackr_phishy_domains`, `shadowtrackr_suppliers`, `shadowtrackr_internet_standards`). Each row has `st_first_synced`, `st_last_synced` and `st_present`; rows ShadowTrackr no longer reports stay for 30 days with `st_present=0`. Per-run counts go to the index for trends. |
| Alert webhook (HEC) | `shadowtrackr:alert` | Configure a ShadowTrackr alert with the "Splunk HEC event" payload, the URL `https://<splunk>:8088/services/collector/event` and the header `Authorization: Splunk <HEC token>`. The index comes from the HEC token. |

Searches use these macros, so the index is set in one place:

| Macro | Expands to |
|---|---|
| `shadowtrackr_index` | `index=shadowtrackr` |
| `shadowtrackr_events` | the events feed |
| `shadowtrackr_webhook_alerts` | alert results pushed by webhook |
| `shadowtrackr_inventory_summary` | per-run inventory counts |

Example: enrich firewall logs with ShadowTrackr's view of the destination:

```
index=firewall | lookup shadowtrackr_hosts ip AS dest_ip OUTPUT services vulnerable problems
```

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

### Fixtures

Never commit raw API responses. Use `tools/redact_events.py` to turn a raw
response into a fixture, then review the result before committing. The v4 fields
in the current fixtures are synthetic (`tools/add_v4_fields.py`) and should be
replaced by redacted live responses.

The dashboards are generated by `tools/gen_dashboards.py`. The app
icons, app-bar logo and dashboard logo tile are generated from
`assets/brand/shadowtrackr-logo.png` by `tools/gen_brand_assets.py` (needs Pillow
and macOS's Avenir Next font for the wordmark).

## License

Apache-2.0
