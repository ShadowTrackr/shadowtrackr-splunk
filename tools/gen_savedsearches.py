#!/usr/bin/env python3
"""Generate the app's detections (package/default/savedsearches.conf).

Usage: python3 -I tools/gen_savedsearches.py

Every detection is defined once below and becomes two saved searches:

- "ShadowTrackr - <name>": a plain Splunk alert (triggered alert, no actions;
  add email, webhook or SOAR actions per site).
- "ShadowTrackr - <name> - Rule": the same search as an Enterprise Security
  correlation search, with a notable event, risk events and MITRE ATT&CK
  annotations. Its notable and risk settings only work where ES is installed.

Health checks and the ES asset lookup generator have no ES twin. Everything
ships disabled.
"""

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "package", "default", "savedsearches.conf")

# Splunk alert.severity: 1 debug, 2 info, 3 warn, 4 error, 5 severe, 6 fatal.
ALERT_SEVERITY = {"informational": 2, "low": 3, "medium": 4, "high": 5, "critical": 6}

# Index-time window for searches over the events feed. The Events input
# collects every 15 minutes and events keep ShadowTrackr's timestamp, so a
# window on _time would miss events that arrive late; the extra five minutes
# overlap the previous run and the throttle drops the repeats. Events older
# than dispatch.earliest_time (7 days) never alert, so a first-run backfill
# does not flood the queue.
EVENTS_WINDOW = "_index_earliest=-20m@m _index_latest=now"

EVENT_TABLE = ("| table _time dest dest_ip dest_port signature signature_id severity message vendor_account link id")

# Inventory rows synced in the last two hours, skipping the initial load: rows
# synced within an hour of the oldest row in the lookup came with the first
# sync, not as new findings.
NEW_INVENTORY = ("| eventstats min(st_first_synced) as st_baseline"
                 " | where st_present=1 AND st_first_synced>=relative_time(now(), \"-2h\")"
                 " AND st_first_synced>st_baseline+3600")

# Port events: the aggregated "Host ports changed" events (281-283) carry a
# ports{} list with a state per port; the older per-port "opened" events carry
# one port and mean open.
PORT_CHANGE_EVENTS = (281, 282, 283)
PORT_OPENED_EVENTS = (201, 203, 218, 221) + tuple(range(209, 218)) + tuple(range(223, 258)) + (264, 267, 274)

# Source addresses that are not on the internet.
PRIVATE_SRC = ('cidrmatch("10.0.0.0/8", src) OR cidrmatch("172.16.0.0/12", src)'
               ' OR cidrmatch("192.168.0.0/16", src) OR cidrmatch("127.0.0.0/8", src)'
               ' OR cidrmatch("100.64.0.0/10", src) OR cidrmatch("169.254.0.0/16", src)'
               ' OR cidrmatch("fc00::/7", src) OR cidrmatch("fe80::/10", src) OR src="::1"')

HOURLY = "{} * * * *"

# Remote-login services, in ShadowTrackr's service names and in the CIM
# Authentication app field (sshd, rdp, ...).
REMOTE_LOGIN = "(?i)ssh|rdp|ms-wbt|terminal|vnc|telnet|winrm|wsman"

# The CVE has an NCSC NL advisory (the KV Store may hold an empty string).
NCSC = '(isnotnull(ncsc) AND ncsc!="")'


def ids(values):
    return ", ".join(str(v) for v in sorted(values))


def events(where, table=EVENT_TABLE):
    return "`shadowtrackr_events` {} {} {}".format(EVENTS_WINDOW, where, table)


def risk(field, kind, score):
    return {"risk_object_field": field, "risk_object_type": kind, "risk_score": score}


def threat(field, kind):
    return {"threat_object_field": field, "threat_object_type": kind}


DETECTIONS = [
    # --- ShadowTrackr findings ------------------------------------------------
    {
        "name": "Problem detected",
        "description": "ShadowTrackr reported a problem (level 90 or higher) on one of your assets. "
                       "Throttled per asset and event type for a day.",
        "search": events("level>=90"),
        "cron": "*/15 * * * *", "earliest": "-7d", "latest": "now",
        "suppress": ("dest,signature_id", "86400s"),
        "severity": "high",
        "domain": "network",
        "title": "ShadowTrackr problem on $dest$: $signature$",
        "notable_description": "ShadowTrackr reported a problem on $dest$: $message$",
        "risk": [risk("dest", "system", 50)],
        "risk_message": "ShadowTrackr problem on $dest$: $signature$",
        "mitre": [],
        "drilldown": ("View the ShadowTrackr events for $dest$",
                      "`shadowtrackr_events` dest=\"$dest$\""),
    },
    {
        "name": "New known exploited vulnerability",
        "description": "A newly found CVE on one of your assets is known to be exploited, is on the CISA KEV list "
                       "or has an NCSC NL advisory. Uses the inventory lookups (run the Inventory input); the "
                       "first inventory sync is the baseline and does not alert. One result per asset, with the severity "
                       "of its worst CVE as ShadowTrackr rates it (from CVSS; unknown when there is no score).",
        "search": "| inputlookup shadowtrackr_cves " + NEW_INVENTORY +
                  " AND coalesce(resolved, 0)!=1 AND (exploited=1 OR cisa_kev=1 OR " + NCSC + ")"
                  " | eval threat_intel=mvappend(if(exploited=1, \"known exploited\", null()),"
                  " if(cisa_kev=1, \"CISA KEV\", null()), if(" + NCSC + ", \"NCSC NL\", null()))"
                  " | eval st_severity_rank=case(severity=\"critical\", 4, severity=\"high\", 3,"
                  " severity=\"medium\", 2, severity=\"low\", 1, true(), 0)"
                  " | stats values(cve) as cve values(software) as software max(cvss) as cvss"
                  " max(st_severity_rank) as st_severity_rank"
                  " values(threat_intel) as threat_intel dc(cve) as cve_count values(organization) as vendor_account"
                  " by asset"
                  " | rename asset as dest"
                  " | eval signature=\"Known exploited vulnerability\","
                  " severity=case(st_severity_rank=4, \"critical\", st_severity_rank=3, \"high\","
                  " st_severity_rank=2, \"medium\", st_severity_rank=1, \"low\", true(), \"unknown\"),"
                  " st_cve_key=mvjoin(mvsort(cve), \",\")"
                  " | table dest cve cve_count cvss threat_intel software signature severity vendor_account st_cve_key",
        "cron": HOURLY.format(35), "earliest": "-24h", "latest": "now",
        "suppress": ("dest,st_cve_key", "604800s"),
        "severity": "high",
        "domain": "network",
        "title": "Known exploited vulnerability on $dest$",
        "notable_description": "ShadowTrackr found $cve_count$ known exploited CVE(s) on $dest$: $cve$ "
                               "($threat_intel$).",
        "risk": [risk("dest", "system", 80), threat("cve", "cve")],
        "risk_message": "Known exploited vulnerability on $dest$: $cve$",
        "mitre": ["T1190"],
        "drilldown": ("View the CVEs on $dest$",
                      "| inputlookup shadowtrackr_cves where asset=\"$dest$\" st_present=1"),
    },
    {
        "name": "Certificate expiring",
        "description": "A certificate on one of your websites expires within `shadowtrackr_cert_expiry_days` "
                       "days (default 14) or expired in the last 30 days, and has not been renewed. Uses the "
                       "inventory lookups.",
        "search": "| inputlookup shadowtrackr_certificates where st_present=1"
                  " | search NOT renewed=1 NOT revoked=1"
                  " | eval days_left=floor((strptime(not_after, \"%Y-%m-%dT%H:%M:%SZ\")-now())/86400)"
                  " | where days_left<=`shadowtrackr_cert_expiry_days` AND days_left>=-30"
                  " | eval dest=url, dest_ip=host, vendor_account=organization,"
                  " signature=if(days_left<0, \"Certificate expired\", \"Certificate expires soon\"),"
                  " severity=case(days_left<0, \"high\", days_left<=7, \"medium\", true(), \"low\")"
                  " | table dest dest_ip cn issuer_cn not_after days_left serial sha256 signature severity"
                  " vendor_account",
        "cron": "30 7 * * *", "earliest": "-24h", "latest": "now",
        "suppress": ("sha256", "604800s"),
        "severity": "medium",
        "domain": "network",
        "title": "$signature$ on $dest$",
        "notable_description": "The certificate for $dest$ ($cn$, issued by $issuer_cn$) expires on $not_after$ "
                               "($days_left$ days).",
        "risk": [risk("dest", "system", 20)],
        "risk_message": "$signature$ on $dest$ ($days_left$ days)",
        "mitre": [],
        "drilldown": ("View the certificates for $dest$",
                      "| inputlookup shadowtrackr_certificates where url=\"$dest$\""),
    },
    {
        "name": "Risky service exposed",
        "description": "ShadowTrackr saw a port open that should rarely face the internet (RDP, SMB, telnet, "
                       "databases, ...). The ports are in the shadowtrackr_risky_ports lookup; point it at your own CSV to "
                       "change the list. Throttled per asset and port for a week.",
        "search": events("(eventid IN ({}) OR eventid IN ({}))".format(ids(PORT_CHANGE_EVENTS),
                                                                     ids(PORT_OPENED_EVENTS)),
                         "| spath path=ports{} output=st_port_entry"
                         " | eval st_port_entry=coalesce(st_port_entry, \"{}\")"
                         " | mvexpand st_port_entry"
                         " | eval dest_port=coalesce(spath(st_port_entry, \"port\"), port),"
                         " st_port_state=coalesce(spath(st_port_entry, \"state\"),"
                         " if(action=\"deleted\", \"closed\", \"open\"))"
                         " | where st_port_state=\"open\""
                         " | lookup shadowtrackr_risky_ports port AS dest_port OUTPUT service reason"
                         " | where isnotnull(service)"
                         " | eval signature=\"Risky service exposed: \".service.\" (\".dest_port.\")\""
                         " | table _time dest dest_ip dest_port service reason signature signature_id severity"
                         " message vendor_account link id"),
        "cron": "*/15 * * * *", "earliest": "-7d", "latest": "now",
        "suppress": ("dest,dest_port", "604800s"),
        "severity": "high",
        "domain": "network",
        "title": "$service$ exposed on $dest$:$dest_port$",
        "notable_description": "ShadowTrackr found $service$ open to the internet on $dest$ port $dest_port$. "
                               "$reason$",
        "risk": [risk("dest", "system", 50)],
        "risk_message": "$service$ exposed to the internet on $dest$:$dest_port$",
        "mitre": ["T1133", "T1190"],
        "drilldown": ("View the ShadowTrackr events for $dest$",
                      "`shadowtrackr_events` dest=\"$dest$\""),
    },
    {
        "name": "Subdomain takeover risk",
        "description": "A possible subdomain takeover, a stale DNS record, or a DNS record that points to a "
                       "domain for sale.",
        "search": events("eventid IN (3312, 3314, 3315)"),
        "cron": "*/15 * * * *", "earliest": "-7d", "latest": "now",
        "suppress": ("dest,signature_id", "604800s"),
        "severity": "high",
        "domain": "threat",
        "title": "$signature$: $dest$",
        "notable_description": "$message$",
        "risk": [risk("dest", "system", 70)],
        "risk_message": "$signature$: $dest$",
        "mitre": ["T1584.001"],
        "drilldown": ("View the ShadowTrackr events for $dest$",
                      "`shadowtrackr_events` dest=\"$dest$\""),
    },
    {
        "name": "Asset blacklisted",
        "description": "One of your IPs or domains appeared on a blacklist, which can mean it sends spam or "
                       "malware, or was compromised.",
        "search": events("eventid=6"),
        "cron": "*/15 * * * *", "earliest": "-7d", "latest": "now",
        "suppress": ("dest", "604800s"),
        "severity": "medium",
        "domain": "threat",
        "title": "$dest$ is blacklisted",
        "notable_description": "$message$",
        "risk": [risk("dest", "system", 40)],
        "risk_message": "$dest$ appeared on a blacklist",
        "mitre": [],
        "drilldown": ("View the ShadowTrackr events for $dest$",
                      "`shadowtrackr_events` dest=\"$dest$\""),
    },
    {
        "name": "Phishy domain found",
        "description": "ShadowTrackr found a new lookalike (phishy) domain of one of your domains, or an existing "
                       "one changed or became suspicious. Block it on the proxy and mail gateway, or monitor it.",
        "search": events("eventid IN (3001, 3002, 3004, 3006, 3316)"),
        "cron": "*/15 * * * *", "earliest": "-7d", "latest": "now",
        "suppress": ("dest,signature_id", "604800s"),
        "severity": "medium",
        "domain": "threat",
        "title": "$signature$: $dest$",
        "notable_description": "$message$",
        "risk": [risk("dest", "other", 40), threat("dest", "domain")],
        "risk_message": "Phishy lookalike domain $dest$",
        "mitre": ["T1583.001", "T1566"],
        "drilldown": ("View the phishy domain $dest$",
                      "| inputlookup shadowtrackr_phishy_domains where phishy_domain=\"$dest$\""),
    },
    {
        "name": "Leaked data found",
        "description": "Your keywords, domains or email addresses showed up in a data breach, a dump or on "
                       "Pastebin.",
        "search": events("eventid IN (8, 2002, 2003, 2004, 3101)"),
        "cron": "*/15 * * * *", "earliest": "-7d", "latest": "now",
        "suppress": ("dest,signature_id", "86400s"),
        "severity": "high",
        "domain": "threat",
        "title": "$signature$: $dest$",
        "notable_description": "$message$",
        "risk": [risk("dest", "other", 50)],
        "risk_message": "$signature$: $dest$",
        "mitre": ["T1589.001"],
        "drilldown": ("View the ShadowTrackr events for $dest$",
                      "`shadowtrackr_events` dest=\"$dest$\""),
    },
    {
        "name": "Webhook alert received",
        "description": "A ShadowTrackr alert pushed a result to Splunk through the HTTP Event Collector "
                       "webhook. Webhook retries are deduplicated.",
        "search": "`shadowtrackr_webhook_alerts` NOT truncated=true " + EVENTS_WINDOW +
                  " | dedup st_result_key"
                  " | table _time dest alert alert_id severity vendor_account st_result_key",
        "cron": "*/15 * * * *", "earliest": "-7d", "latest": "now",
        "suppress": ("st_result_key", "86400s"),
        "severity": "medium",
        "domain": "threat",
        "title": "ShadowTrackr alert $alert$ on $dest$",
        "notable_description": "The ShadowTrackr alert \"$alert$\" fired for $dest$.",
        "risk": [risk("dest", "system", 40)],
        "risk_message": "ShadowTrackr alert $alert$ on $dest$",
        "mitre": [],
        "drilldown": ("View the webhook alerts for $dest$",
                      "`shadowtrackr_webhook_alerts` dest=\"$dest$\""),
    },
    # --- Your logs plus ShadowTrackr ------------------------------------------
    {
        "name": "Attack on vulnerable asset",
        "description": "Your IDS, IPS or WAF saw attacks on an asset where ShadowTrackr found CVEs. The severity is "
                       "that of the worst CVE on the asset (from CVSS; unknown when there is no score). Reads the "
                       "shadowtrackr_asset_ids macro (CIM Intrusion Detection tags by default).",
        "search": "`shadowtrackr_asset_ids`"
                  " | stats count min(_time) as firstTime max(_time) as lastTime values(signature) as signature"
                  " values(src) as src dc(src) as src_count values(sourcetype) as sourcetype by dest"
                  " | stenrich field=dest"
                  " | where st_vulnerable=1"
                  " | eval severity=`shadowtrackr_cvss_severity(st_max_cvss)`,"
                  " src=mvindex(src, 0, 9), signature=mvindex(signature, 0, 9)"
                  " | table dest count firstTime lastTime src src_count signature sourcetype severity st_cves"
                  " st_max_cvss st_exploited st_cisa_kev st_organization",
        "cron": HOURLY.format(5), "earliest": "-65m@m", "latest": "-5m@m",
        "suppress": ("dest", "86400s"),
        "severity": "high",
        "domain": "network",
        "title": "Attacks on vulnerable asset $dest$",
        "notable_description": "$count$ IDS/WAF events from $src_count$ source(s) hit $dest$, where ShadowTrackr "
                               "found these CVEs: $st_cves$.",
        "risk": [risk("dest", "system", 80), threat("src", "ip_address")],
        "risk_message": "Attacks on $dest$, which has known CVEs",
        "mitre": ["T1190"],
        "drilldown": ("View the IDS events for $dest$",
                      "`shadowtrackr_asset_ids` dest=\"$dest$\""),
    },
    {
        "name": "Web traffic to phishy domain",
        "description": "A user or host visited a lookalike (phishy) domain of one of your domains. Reads the "
                       "shadowtrackr_asset_web macro (CIM Web tags by default), so it needs proxy logs.",
        "search": "`shadowtrackr_asset_web`"
                  " | eval st_web_host=coalesce(url_domain, dest, url)"
                  " | stats count min(_time) as firstTime max(_time) as lastTime values(src) as src"
                  " values(user) as user values(url) as url by st_web_host"
                  " | stenrich field=st_web_host"
                  " | where st_phishy=1"
                  " | eval dest=st_web_host, severity=\"high\", url=mvindex(url, 0, 9)"
                  " | table dest count firstTime lastTime src user url st_lookalike_of st_phishy_score severity",
        "cron": HOURLY.format(10), "earliest": "-65m@m", "latest": "-5m@m",
        "suppress": ("dest", "86400s"),
        "severity": "high",
        "domain": "threat",
        "title": "Web traffic to phishy domain $dest$",
        "notable_description": "$src$ visited $dest$, a lookalike of $st_lookalike_of$.",
        "risk": [risk("src", "system", 60), risk("user", "user", 60), threat("dest", "domain")],
        "risk_message": "Visited phishy lookalike domain $dest$",
        "mitre": ["T1566.002"],
        "drilldown": ("View the web traffic to $dest$",
                      "`shadowtrackr_asset_web` (url_domain=\"$dest$\" OR dest=\"$dest$\")"),
    },
    {
        "name": "External login on exposed remote access",
        "description": "A successful remote login (SSH, RDP, VNC, telnet, WinRM; logins without an app field count "
                       "too) from an internet address on an asset where ShadowTrackr sees such a service open to "
                       "the internet. Reads the "
                       "shadowtrackr_asset_auth macro (CIM Authentication tags by default).",
        "search": "`shadowtrackr_asset_auth` action=success"
                  " | fillnull value=\"unknown\" app"
                  " | where app=\"unknown\" OR match(app, \"" + REMOTE_LOGIN + "\")"
                  " | stats count min(_time) as firstTime max(_time) as lastTime values(app) as app"
                  " by dest user src"
                  " | where match(src, \"^[0-9a-fA-F:.]+$\") AND NOT (" + PRIVATE_SRC + ")"
                  " | stenrich field=dest"
                  " | where st_known=1"
                  " AND match(mvjoin(st_services, \" \"), \"" + REMOTE_LOGIN + "\")"
                  " | eval severity=\"medium\""
                  " | table dest user src count firstTime lastTime app st_services severity st_organization",
        "cron": HOURLY.format(15), "earliest": "-65m@m", "latest": "-5m@m",
        "suppress": ("dest,user,src", "86400s"),
        "severity": "medium",
        "domain": "access",
        "title": "External login by $user$ on $dest$ from $src$",
        "notable_description": "$user$ logged in on $dest$ from $src$. ShadowTrackr sees these services open to "
                               "the internet on $dest$: $st_services$.",
        "risk": [risk("user", "user", 30), risk("dest", "system", 30), threat("src", "ip_address")],
        "risk_message": "External login by $user$ on internet-facing $dest$ from $src$",
        "mitre": ["T1133", "T1078"],
        "drilldown": ("View the logins on $dest$",
                      "`shadowtrackr_asset_auth` dest=\"$dest$\""),
    },
]

HEALTH = [
    {
        "name": "Health - No events received",
        "description": "The ShadowTrackr Events input indexed nothing in the last 24 hours. Check the input and "
                       "the shadowtrackr_*.log files in index=_internal.",
        "search": "| tstats count max(_indextime) as last_indexed where `shadowtrackr_events`"
                  " | eval hours_since=round((now()-last_indexed)/3600, 1),"
                  " last_indexed=strftime(last_indexed, \"%F %T %Z\"), st_check=\"events\""
                  " | where isnull(hours_since) OR hours_since>24"
                  " | table st_check last_indexed hours_since",
        "cron": HOURLY.format(50), "earliest": "-30d", "latest": "now",
        "suppress": ("st_check", "86400s"),
        "severity": "medium",
    },
    {
        "name": "Health - Input errors",
        "description": "The ShadowTrackr inputs logged errors in the last hour (API errors, bad API key, KV "
                       "Store). Needs access to index=_internal.",
        "search": "index=_internal source=*shadowtrackr_*.log* log_level=ERROR"
                  # The message, or the last line of the traceback, which has the reason.
                  " | eval error=trim(replace(mvindex(split(_raw, urldecode(\"%0A\")), -1), \"^.*?\\| \", \"\"))"
                  " | stats count latest(_time) as last_error latest(error) as error by source"
                  " | eval last_error=strftime(last_error, \"%F %T %Z\")"
                  " | table source count last_error error",
        "cron": HOURLY.format(55), "earliest": "-65m@m", "latest": "-5m@m",
        "suppress": ("source", "21600s"),
        "severity": "medium",
    },
    {
        "name": "Health - Inventory stale",
        "description": "An inventory type failed on its last sync, or has not synced for 4 days (the default "
                       "schedule skips weekends).",
        "search": "`shadowtrackr_inventory_summary`"
                  " | fillnull value=\"-\" organization"
                  " | stats latest(_time) as last_sync latest(status) as status latest(error) as error"
                  " by input organization type"
                  " | eval hours_since=round((now()-last_sync)/3600, 1),"
                  " last_sync=strftime(last_sync, \"%F %T %Z\")"
                  " | where status=\"error\" OR hours_since>96"
                  " | table input organization type status error last_sync hours_since",
        "cron": "0 9 * * *", "earliest": "-14d", "latest": "now",
        "suppress": ("input,organization,type", "86400s"),
        "severity": "low",
    },
]

# ES asset lookup: one row per host and website from the inventory, in the ES
# asset format. Register shadowtrackr_es_assets in ES under Configure > Data
# Enrichment > Asset and Identity Management.
ES_ASSET_FIELDS = ("ip mac nt_host dns owner priority lat long city country bunit category pci_domain"
                   " is_expected should_timesync should_update requires_av")
ES_ASSET_LOOKUP = {
    "name": "ES asset lookup - Lookup Gen",
    "description": "Builds the shadowtrackr_es_assets lookup in the Enterprise Security asset format from the "
                   "inventory: every internet-facing host and website. The priority is the severity of the worst CVE "
                   "on the asset as ShadowTrackr rates it (from CVSS), or unknown when it has no scored CVEs. Register the lookup in ES "
                   "under Configure > Data Enrichment > Asset and Identity Management.",
    "search": "| inputlookup shadowtrackr_hosts where st_present=1"
              " | eval st_key=ip, dns=hostnames"
              " | append [| inputlookup shadowtrackr_websites where st_present=1"
              " | eval st_key=url, dns=url, ip=if(match(host, \"^[0-9a-fA-F:.]+$\"), host, null())]"
              " | stenrich field=st_key"
              " | eval priority=`shadowtrackr_cvss_severity(st_max_cvss)`,"
              " bunit=organization, category=\"shadowtrackr|internet_facing\", is_expected=\"true\","
              " ip=mvjoin(ip, \"|\"), dns=mvjoin(mvdedup(dns), \"|\")"
              " | table " + ES_ASSET_FIELDS +
              " | outputlookup shadowtrackr_es_assets",
    "cron": "15 17 * * *", "earliest": "-24h", "latest": "now",
}


def conf_value(text):
    """A conf value: long SPL is split over lines at pipes with backslash continuations."""
    return text.replace(" | ", " \\\n| ")


def stanza(name, settings):
    lines = ["[{}]".format(name)]
    for key, value in settings:
        lines.append("{} = {}".format(key, conf_value(value) if key == "search" else value))
    return "\n".join(lines)


def schedule(d):
    return [
        ("cron_schedule", d["cron"]),
        ("dispatch.earliest_time", d["earliest"]),
        ("dispatch.latest_time", d["latest"]),
        ("enableSched", "1"),
        ("schedule_window", "auto"),
    ]


def alert_settings(d):
    fields, period = d["suppress"]
    return [
        ("counttype", "number of events"),
        ("relation", "greater than"),
        ("quantity", "0"),
        ("alert.digest_mode", "0"),
        ("alert.suppress", "1"),
        ("alert.suppress.fields", fields),
        ("alert.suppress.period", period),
        ("alert.severity", str(ALERT_SEVERITY[d["severity"]])),
        ("alert.track", "1"),
    ]


def common(d):
    return [
        ("disabled", "1"),
        ("description", d["description"]),
        ("search", d["search"]),
        ("request.ui_dispatch_app", "shadowtrackr"),
        ("request.ui_dispatch_view", "search"),
    ]


def plain(d):
    name = "ShadowTrackr - " + d["name"]
    return stanza(name, common(d) + schedule(d) + alert_settings(d))


def es_rule(d):
    name = "ShadowTrackr - {} - Rule".format(d["name"])
    annotations = {"mitre_attack": d["mitre"]} if d["mitre"] else {}
    drilldown_name, drilldown_search = d["drilldown"]
    settings = common(d) + schedule(d) + alert_settings(d) + [
        ("action.correlationsearch.enabled", "1"),
        ("action.correlationsearch.label", name),
        ("action.correlationsearch.annotations", json.dumps(annotations)),
        ("action.notable", "1"),
        ("action.notable.param.rule_title", d["title"]),
        ("action.notable.param.rule_description", d["notable_description"]),
        ("action.notable.param.security_domain", d["domain"]),
        ("action.notable.param.severity", d["severity"]),
        ("action.notable.param.nes_fields", d["suppress"][0]),
        ("action.notable.param.drilldown_name", drilldown_name),
        ("action.notable.param.drilldown_search", drilldown_search),
        ("action.notable.param.drilldown_earliest_offset", "$info_min_time$"),
        ("action.notable.param.drilldown_latest_offset", "$info_max_time$"),
        ("action.risk", "1"),
        ("action.risk.param._risk", json.dumps(d["risk"])),
        ("action.risk.param._risk_message", d["risk_message"]),
        ("action.risk.param._risk_score", "0"),
        ("action.risk.param.verbose", "0"),
    ]
    return stanza(name, settings)


def health(d):
    name = "ShadowTrackr - " + d["name"]
    return stanza(name, common(d) + schedule(d) + alert_settings(d))


def lookup_gen(d):
    name = "ShadowTrackr - " + d["name"]
    return stanza(name, common(d) + schedule(d))


def build():
    parts = [
        "# Generated by tools/gen_savedsearches.py. Do not edit by hand; change the",
        "# generator and run `make savedsearches`.",
        "#",
        "# Everything ships disabled. Enable a detection under Settings > Searches,",
        "# reports, and alerts (app: ShadowTrackr) and add alert actions there.",
        "# The \"- Rule\" searches are Enterprise Security correlation searches; enable",
        "# them in ES under Content Management instead.",
        "",
        "# --- Detections -----------------------------------------------------------------",
        "",
    ]
    parts += [plain(d) + "\n" for d in DETECTIONS]
    parts += ["# --- Health -----------------------------------------------------------------", ""]
    parts += [health(d) + "\n" for d in HEALTH]
    parts += ["# --- Enterprise Security ------------------------------------------------------",
              "# Correlation searches: notable and risk events, MITRE ATT&CK annotations.", ""]
    parts += [es_rule(d) + "\n" for d in DETECTIONS]
    parts += [lookup_gen(ES_ASSET_LOOKUP) + "\n"]
    return "\n".join(parts)


def main():
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(build())
    print("Wrote {} ({} detections, {} health checks)".format(os.path.relpath(OUT, ROOT), len(DETECTIONS),
                                                            len(HEALTH)))


if __name__ == "__main__":
    main()
