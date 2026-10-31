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
4. Open the **Overview** dashboard.

## What gets collected

| Input | Sourcetype | Notes |
|---|---|---|
| ShadowTrackr Events | `shadowtrackr:events` | Polls `/events` with explicit start/stop windows and keeps its own checkpoint in the KV Store. It does not use `update_only`, so other API consumers are not affected. |

Events are mapped to the CIM **Alerts** (level 80+), **Change** and
**Vulnerabilities** data models through event types and the
`shadowtrackr_event_types` lookup, which gives every ShadowTrackr event type a
`signature` and category. The Overview dashboard lists event types that are not in
the lookup yet.

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
- API key: `mock-api-key-0000000000`

The mock mimics the real API's behaviour (invalid key returns HTTP 200 with an
error, unknown endpoints return HTML) and has fault injection keys:
`mock-error-500`, `mock-error-429`, `mock-error-slow` and `mock-error-html`.

### Fixtures

Never commit raw API responses. Use `tools/redact_events.py` to turn a raw
response into a fixture, then review the result before committing.

## License

Apache-2.0
