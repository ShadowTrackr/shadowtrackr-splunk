ShadowTrackr app for Splunk
===========================

Brings data from ShadowTrackr (External Attack Surface Management) into Splunk,
so SOC teams can alert on it, enrich their logs with it and explore it in
dashboards.

- Events input: polls the ShadowTrackr /events API into the shadowtrackr:events
  sourcetype.
- Inventory input: syncs hosts, websites, domains, certificates, CVEs and more
  into KV Store lookups.
- Alert webhook: receives ShadowTrackr alert results through HEC
  (sourcetype shadowtrackr:alert).
- Dashboards: Overview, Vulnerabilities & software, Certificates, Supplier
  dependency, Asset 360 and Search explorer.
- Detections (shipped disabled) and Enterprise Security correlation searches
  and asset lookup.
- Search commands: | stenrich (enrich any search with ShadowTrackr context)
  and | shadowtrackr (live API queries, admin only).

Requirements
------------
- A ShadowTrackr Business or Enterprise subscription (for API access).
- Splunk Enterprise or Splunk Cloud Platform with the KV Store enabled.
  Tested on Splunk Enterprise 10.2 and 9.4.

Setup
-----
1. Install the app and create an index named "shadowtrackr".
2. In the app, go to Configuration > Accounts and add your ShadowTrackr API key.
3. Go to Inputs and create the ShadowTrackr Events and Inventory inputs.
4. Optional: receive ShadowTrackr alerts by webhook through HEC, enable the
   detections you want (all ship disabled), and point the log macros at your
   indexes. The full setup guide is at
   https://github.com/ShadowTrackr/shadowtrackr-splunk#setup

Release notes
-------------
1.2.0
- Every CVE now has its ShadowTrackr score, and CVSS scores keep their
  decimal (needs the ShadowTrackr API update of November 2026).
- Resolved CVE findings are marked resolved instead of looking open. The
  Vulnerabilities dashboard shows open findings by default, with a Status
  filter, a Resolved findings tile and a Status column; Asset 360 shows the
  status too. | stenrich, the ES asset priority and the "New known
  exploited vulnerability" detection count open findings only. The CVE
  trend counts open findings from the first inventory sync after the
  upgrade, so it drops once.

1.1.0
- First Splunkbase release.
- Events, Inventory and alert webhook inputs; | stenrich and | shadowtrackr
  search commands; six dashboards including Supplier dependency; detections
  and Enterprise Security correlation searches and asset lookup.
- Scoped API keys: expiry, IP allowlist and group read-only keys.

Website: https://shadowtrackr.com

Documentation: https://shadowtrackr.com/docs

Privacy policy: https://shadowtrackr.com/privacy-policy

Support: support@shadowtrackr.com

License: Apache License 2.0 (see LICENSES/LICENSE.txt)
