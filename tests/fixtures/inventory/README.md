# Inventory fixtures

Redacted samples of the ShadowTrackr v4 list endpoints, built with
`tools/make_inventory_fixtures.py` from live responses of a test account
(up to 25 records per endpoint, some fields dropped, everything identifying
replaced by example domains and documentation IP ranges).

`subnets.json`, `mailservers.json`, `remote_login_services.json` and
`blacklisted_assets.json` are **synthetic**: the test account has no data for
them. Their field names follow the v3 API documentation and must be replaced
by redacted real responses.

`suppliers.json` is the live answer of `/query` with `q=index=suppliers`, not of
the `/suppliers` list endpoint: the sync reads suppliers through `/query`
because only that has `country`, `city` and `control`. Supplier names are
public companies and are kept.
