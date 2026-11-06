#!/usr/bin/env python3
"""Generate the app's Dashboard Studio views (package/default/data/ui/views).

Usage: python3 -I tools/gen_dashboards.py

All dashboards share the same header, colours and filter behaviour.
"""

import json
import os
from xml.sax.saxutils import escape

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VIEWS = os.path.join(ROOT, "package", "default", "data", "ui", "views")

# Status colours, validated for the dark surface (#171d21) with the dataviz
# palette validator: lightness band, CVD separation and 3:1 contrast all pass.
PROBLEM = "#d03b3b"
WARNING = "#c98500"
INFO = "#3987e5"
NEUTRAL = "#c3c2b7"  # secondary text on the dark surface

HEADER = 90

# Inventory trend from the summary events: the latest count per input and
# organization per day, summed across organizations. The inventory syncs on
# weekdays during office hours, so days without a sync (weekends) carry the
# last count forward instead of dropping to a gap.
TREND = (' | fillnull value="-" organization | bin _time span=1d'
         ' | stats latest(present) as present by _time, input, organization'
         ' | timechart span=1d sum(present) as "{label}" | filldown "{label}"')
TIME_TOKENS = {"earliest": "$global_time.earliest$", "latest": "$global_time.latest$"}


# --- building blocks ----------------------------------------------------------


def ds(name, query, time=True):
    options = {"query": query}
    if time:
        options["queryParameters"] = TIME_TOKENS
    return {"type": "ds.search", "name": name, "options": options}


def single(title, ds_id, color=None, sparkline=False):
    viz = {"type": "splunk.singlevalue", "title": title, "dataSources": {"primary": ds_id},
           "options": {"sparklineDisplay": "below" if sparkline else "off", "trendDisplay": "off"}}
    if color:
        # Colour only when there is something to act on; zero stays neutral.
        viz["options"]["majorColor"] = "> majorValue | rangeValue(majorColorConfig)"
        viz["context"] = {"majorColorConfig": [{"to": 1, "value": NEUTRAL}, {"from": 1, "to": 1e15, "value": color}]}
    if sparkline:
        viz["options"]["sparklineStrokeColor"] = INFO
    return viz


def bar(title, ds_id, kind="splunk.bar"):
    return {
        "type": kind, "title": title, "dataSources": {"primary": ds_id},
        "options": {"legendDisplay": "off", "seriesColors": [INFO], "dataValuesDisplay": "all",
                    "xAxisTitleVisibility": "hide", "yAxisTitleVisibility": "hide"},
    }


def table(title, ds_id, count=10, description=None, url=None, hide_when_empty=False, new_tab=True):
    viz = {"type": "splunk.table", "title": title, "dataSources": {"primary": ds_id}, "options": {"count": count}}
    if description:
        viz["description"] = description
    if url:
        viz["eventHandlers"] = [{"type": "drilldown.customUrl", "options": {"url": url, "newTab": new_tab}}]
    if hide_when_empty:
        viz["hideWhenNoData"] = True
    return viz


def asset_table(title, ds_id, column, count=10, description=None):
    """A table whose rows open Asset 360 for the value in column."""
    note = "Click a row to open the asset in Asset 360."
    return table(title, ds_id, count=count, description=(description + " " + note) if description else note,
                 url="/app/shadowtrackr/shadowtrackr_asset?form.asset=$row.{}.value$".format(column), new_tab=False)


def markdown(text):
    return {"type": "splunk.markdown", "options": {"markdown": text, "fontColor": NEUTRAL}}


def chain(name, extend, query):
    return {"type": "ds.chain", "name": name, "options": {"extend": extend, "query": query}}


def header(subtitle):
    markdown = (
        "## ShadowTrackr\n" + subtitle + " · "
        "[Open ShadowTrackr](https://shadowtrackr.com/usr/) · [Documentation](https://shadowtrackr.com/docs)"
    )
    return {
        "viz_logo": {
            "type": "splunk.image",
            "options": {"src": "/static/app/shadowtrackr/images/logo_tile.png", "preserveAspectRatio": True},
            "eventHandlers": [{"type": "drilldown.customUrl",
                               "options": {"url": "https://shadowtrackr.com/usr/", "newTab": True}}],
        },
        "viz_title": {"type": "splunk.markdown", "options": {"markdown": markdown}},
    }


def org_input(query):
    """Organization dropdown. The query must return label/value rows; "All" is always first."""
    return {
        "type": "input.dropdown", "title": "Organization",
        "dataSources": {"primary": "ds_orgs"},
        "options": {"token": "org", "defaultValue": "*", "items": ">frame(label, value) | objects()"},
        "context": {
            "label": '>primary | seriesByName("label") | renameSeries("label") | formatByType(formattedConfig)',
            "value": '>primary | seriesByName("value") | renameSeries("value") | formatByType(formattedConfig)',
            "formattedConfig": {"number": {"prefix": ""}},
        },
    }, ds("Organizations", query
          + " | eval label=org_name, value=org_name, order=1"
          ' | append [| makeresults | eval label="All organizations", value="*", order=0]'
          " | sort order label | table label value", time=False)


TIME_INPUT = {"type": "input.timerange", "title": "Time range",
              "options": {"token": "global_time", "defaultValue": "-7d@h,now"}}


def dashboard(name, label, description, subtitle, inputs, data_sources, visualizations, rows, layout_options=None):
    vizs = dict(header(subtitle), **visualizations)
    layout = [("viz_logo", 0, 0, 90, HEADER), ("viz_title", 90, 0, 1110, HEADER)]
    layout += [(item, x, y + HEADER, w, h) for item, x, y, w, h in rows]
    definition = {
        "title": label,
        "description": description,
        "inputs": inputs,
        "defaults": {},
        "visualizations": vizs,
        "dataSources": data_sources,
        "layout": {
            "type": "grid",
            "options": dict({"width": 1200}, **(layout_options or {})),
            "globalInputs": list(inputs),
            "structure": [{"item": i, "type": "block", "position": {"x": x, "y": y, "w": w, "h": h}}
                          for i, x, y, w, h in layout],
        },
    }
    xml = """<dashboard version="2" theme="dark">
    <label>{label}</label>
    <description>{description}</description>
    <definition><![CDATA[
{definition}
    ]]></definition>
    <meta type="hiddenElements"><![CDATA[
{{
    "hideEdit": false,
    "hideOpenInSearch": false,
    "hideExport": false
}}
    ]]></meta>
</dashboard>
""".format(label=escape(label), description=escape(description), definition=json.dumps(definition, indent=4))
    path = os.path.join(VIEWS, name + ".xml")
    with open(path, "w", encoding="utf-8") as f:
        f.write(xml)
    print("wrote", os.path.relpath(path, ROOT))


# --- Overview -------------------------------------------------------------------

# Status shown as icon + label, so it never relies on colour alone.
STATUS_LABEL = 'eval Status=case(level>=90, "▲ Problem", level>=80, "■ Warning", true(), "● Info")'


def overview():
    base = '`shadowtrackr_events` | where "$org$"="*" OR vendor_account="$org$"'
    alerts = base + " | where level>=$min_level$"
    def surface(title):
        inv_type, label = title
        return ('`shadowtrackr_inventory_summary` status=ok type={} | where "$org$"="*" OR organization="$org$"'
                + TREND).format(inv_type, label=label)

    org, ds_orgs = org_input("`shadowtrackr_events` vendor_account=* | stats count by vendor_account"
                             " | rename vendor_account AS org_name")
    ds_orgs["options"]["queryParameters"] = {"earliest": "-30d", "latest": "now"}
    data_sources = {
        "ds_total": ds("Total events", base + " | stats count"),
        "ds_problems": ds("Problems", base + " | where level>=90 | stats count"),
        "ds_warnings": ds("Warnings", base + " | where level>=80 AND level<90 | stats count"),
        "ds_assets": ds("Assets with events", base + " | stats dc(dest) as assets"),
        "ds_hosts": ds("Hosts", surface(("hosts", "Hosts"))),
        "ds_websites": ds("Websites", surface(("websites", "Websites"))),
        "ds_certs": ds("Certificates", surface(("certificates", "Certificates"))),
        "ds_cves": ds("CVEs", surface(("cves", "CVE findings"))),
        "ds_timeline": ds(
            "Events over time",
            base + ' | eval Status=case(level>=90, "Problems", level>=80, "Warnings", true(), "Info")'
            " | timechart count by Status | fillnull value=0 Problems Warnings Info"
            " | table _time Problems Warnings Info",
        ),
        "ds_category": ds(
            "Events by category",
            base + ' | eval Category=coalesce(st_category, "unclassified") | stats count as Events by Category'
                   " | sort - Events",
        ),
        "ds_latest": ds(
            "Latest alerts",
            alerts + " | sort - _time | head 100 | " + STATUS_LABEL
            + ' | eval Time=strftime(_time, "%Y-%m-%d %H:%M")'
            " | rename dest AS Asset, signature AS Alert | table Time Status Asset Alert",
        ),
        "ds_top_assets": ds(
            "Assets with most alerts",
            alerts + ' | stats count as Alerts max(level) as level latest(signature) as "Latest alert" by dest'
            " | sort - level - Alerts | head 20 | " + STATUS_LABEL
            + ' | rename dest AS Asset | table Asset Status Alerts "Latest alert"',
        ),
        "ds_changes": ds(
            "Changes by type",
            base + " | search eventtype=shadowtrackr_change | stats count as Changes by signature"
            " | rename signature AS Change | sort - Changes | head 10",
        ),
        "ds_unclassified": ds(
            "Unclassified event types",
            base + " | search NOT signature=* | stats count as Events latest(message) as Example by eventid category"
            ' | rename eventid AS "Event id", category AS Source | sort - Events',
        ),
        "ds_orgs": ds_orgs,
    }
    visualizations = {
        "viz_total": single("Events", "ds_total"),
        "viz_problems": single("▲ Problems (level 90+)", "ds_problems", PROBLEM),
        "viz_warnings": single("■ Warnings (level 80-89)", "ds_warnings", WARNING),
        "viz_assets": single("Assets with events", "ds_assets"),
        "viz_hosts": single("Hosts", "ds_hosts", sparkline=True),
        "viz_websites": single("Websites", "ds_websites", sparkline=True),
        "viz_certs": single("Certificates", "ds_certs", sparkline=True),
        "viz_cves": single("CVE findings", "ds_cves", sparkline=True),
        "viz_timeline": {
            "type": "splunk.column", "title": "Events over time", "dataSources": {"primary": "ds_timeline"},
            "options": {"stackMode": "stacked", "legendDisplay": "top",
                        "seriesColorsByField": {"Problems": PROBLEM, "Warnings": WARNING, "Info": INFO},
                        "xAxisTitleVisibility": "hide", "yAxisTitleVisibility": "hide"},
        },
        "viz_category": bar("Events by category", "ds_category"),
        "viz_latest": table("Latest alerts", "ds_latest", description="Problems only, or problems and warnings, "
                            "depending on the Alerts filter. Click a row to see the event."),
        "viz_top_assets": asset_table("Assets with the most alerts", "ds_top_assets", "Asset", count=9),
        "viz_changes": table("Top changes", "ds_changes"),
        "viz_unclassified": table(
            "Event types without a classification", "ds_unclassified", count=5, hide_when_empty=True,
            description="The app refreshes the event type catalogue from the API daily; "
                        "types listed here are not in it yet."),
    }
    inputs = {
        "input_time": TIME_INPUT,
        "input_level": {
            "type": "input.dropdown", "title": "Alerts",
            "options": {"token": "min_level", "defaultValue": "90",
                        "items": [{"label": "Problems only (90+)", "value": "90"},
                                  {"label": "Problems and warnings (80+)", "value": "80"}]},
        },
        "input_org": org,
    }
    rows = [
        ("viz_total", 0, 0, 300, 110), ("viz_problems", 300, 0, 300, 110),
        ("viz_warnings", 600, 0, 300, 110), ("viz_assets", 900, 0, 300, 110),
        ("viz_hosts", 0, 110, 300, 120), ("viz_websites", 300, 110, 300, 120),
        ("viz_certs", 600, 110, 300, 120), ("viz_cves", 900, 110, 300, 120),
        ("viz_timeline", 0, 230, 800, 320), ("viz_category", 800, 230, 400, 320),
        ("viz_latest", 0, 550, 1200, 400),
        ("viz_top_assets", 0, 950, 760, 440), ("viz_changes", 760, 950, 440, 440),
        ("viz_unclassified", 0, 1390, 1200, 250),
    ]
    dashboard("shadowtrackr_overview", "Overview",
              "Events from your external attack surface, collected by the ShadowTrackr events input.",
              "External attack surface monitoring", inputs, data_sources, visualizations, rows)


# --- Vulnerabilities & software --------------------------------------------------


def lookup(name):
    return ('| inputlookup shadowtrackr_{} where st_present=1'
            ' | where "$org$"="*" OR organization="$org$"').format(name)


def lookup_orgs():
    return org_input("| inputlookup shadowtrackr_hosts | stats count by organization"
                     " | rename organization AS org_name")


SEVERITY_ORDER = 'eval order=case(severity="critical",1, severity="high",2, severity="medium",3, ' \
                 'severity="low",4, true(),5)'


def vulnerabilities():
    cves = lookup("cves") + " | where coalesce(cvss, 0)>=$min_cvss$ AND ($exploited$)"
    software = lookup("software")
    org, ds_orgs = lookup_orgs()
    data_sources = {
        "ds_cves": ds("Distinct CVEs", cves + " | stats dc(cve) as CVEs", time=False),
        "ds_critical": ds("Critical CVEs", cves + " | where cvss>=9 | stats dc(cve) as Critical", time=False),
        "ds_exploited": ds("Exploited CVEs", cves + " | where exploited=1 | stats dc(cve) as Exploited", time=False),
        "ds_assets": ds("Affected assets", cves + " | stats dc(asset) as Assets", time=False),
        "ds_severity": ds(
            "CVEs by severity",
            cves + ' | eval severity=coalesce(severity, "unknown") | stats dc(cve) as CVEs by severity | '
            + SEVERITY_ORDER + ' | sort order | eval Severity=upper(substr(severity,1,1)).substr(severity,2)'
            " | table Severity CVEs", time=False),
        "ds_trend": ds("CVE findings over time",
                       ('`shadowtrackr_inventory_summary` type=cves status=ok'
                        ' | where "$org$"="*" OR organization="$org$"' + TREND).format(label="CVE findings")),
        "ds_top_cves": ds(
            "Top CVEs",
            cves + " | stats max(cvss) as CVSS max(exploited) as exploited max(cisa_kev) as kev"
            " dc(asset) as Assets values(software) as Software by cve"
            ' | eval Flags=trim(if(exploited=1, "⚠ Exploited ", "").if(kev=1, "◆ CISA KEV", ""))'
            " | sort - exploited - CVSS - Assets | rename cve AS CVE"
            " | table CVE CVSS Flags Assets Software", time=False),
        "ds_software": ds(
            "Software with known CVEs",
            software + " | where cve_count>0 | sort - exploited - max_cvss - asset_count"
            ' | eval Flags=trim(if(exploited=1, "⚠ Exploited ", "").if(cisa_kev=1, "◆ CISA KEV", ""))'
            ' | rename software AS Software, asset_count AS Assets, cve_count AS CVEs, max_cvss AS "Max CVSS"'
            ' | table Software Assets CVEs "Max CVSS" Flags', time=False),
        "ds_asset_risk": ds(
            "Assets with the most serious CVEs",
            cves + " | stats max(cvss) as \"Max CVSS\" dc(cve) as CVEs sum(exploited) as Exploited by asset"
            ' | sort - "Max CVSS" - Exploited - CVEs | rename asset AS Asset | table Asset "Max CVSS" CVEs Exploited',
            time=False),
        "ds_orgs": ds_orgs,
    }
    visualizations = {
        "viz_cves": single("CVEs", "ds_cves"),
        "viz_critical": single("▲ Critical (CVSS 9+)", "ds_critical", PROBLEM),
        "viz_exploited": single("⚠ Known exploited", "ds_exploited", PROBLEM),
        "viz_assets": single("Affected assets", "ds_assets"),
        "viz_severity": bar("CVEs by severity", "ds_severity", kind="splunk.column"),
        "viz_trend": {
            "type": "splunk.line", "title": "CVE findings over time", "dataSources": {"primary": "ds_trend"},
            "options": {"legendDisplay": "off", "seriesColors": [INFO],
                        "xAxisTitleVisibility": "hide", "yAxisTitleVisibility": "hide"},
        },
        "viz_top_cves": table("Top CVEs", "ds_top_cves", description="Exploited first, then by CVSS. "
                              "Click a row to open the CVE at NVD.",
                              url="https://nvd.nist.gov/vuln/detail/$row.CVE.value$"),
        "viz_software": table("Software with known CVEs", "ds_software", count=9),
        "viz_asset_risk": asset_table("Assets with the most serious CVEs", "ds_asset_risk", "Asset", count=9),
    }
    inputs = {
        "input_cvss": {
            "type": "input.dropdown", "title": "Minimum CVSS",
            "options": {"token": "min_cvss", "defaultValue": "0",
                        "items": [{"label": "All", "value": "0"}, {"label": "4+ (medium)", "value": "4"},
                                  {"label": "7+ (high)", "value": "7"}, {"label": "9+ (critical)", "value": "9"}]},
        },
        "input_exploited": {
            "type": "input.dropdown", "title": "Exploited",
            "options": {"token": "exploited", "defaultValue": "true()",
                        "items": [{"label": "All CVEs", "value": "true()"},
                                  {"label": "Known exploited only", "value": "exploited=1"}]},
        },
        "input_org": org,
        "input_time": dict(TIME_INPUT, title="Trend period"),
    }
    rows = [
        ("viz_cves", 0, 0, 300, 110), ("viz_critical", 300, 0, 300, 110),
        ("viz_exploited", 600, 0, 300, 110), ("viz_assets", 900, 0, 300, 110),
        ("viz_severity", 0, 110, 500, 300), ("viz_trend", 500, 110, 700, 300),
        ("viz_top_cves", 0, 410, 1200, 420),
        ("viz_software", 0, 830, 600, 420), ("viz_asset_risk", 600, 830, 600, 420),
    ]
    dashboard("shadowtrackr_vulnerabilities", "Vulnerabilities & software",
              "CVEs and software that ShadowTrackr found on your internet-facing assets, from the inventory lookups.",
              "Vulnerabilities and software", inputs, data_sources, visualizations, rows)


# --- Certificates ---------------------------------------------------------------------


def certificates():
    certs = lookup("certificates") + (
        ' | eval days_left=floor((strptime(not_after, "%Y-%m-%dT%H:%M:%SZ") - now()) / 86400)')
    org, ds_orgs = lookup_orgs()
    expiry = (' | eval Expiry=case(days_left<0, "▲ Expired", days_left<=7, "▲ Within 7 days", '
              'days_left<=30, "■ Within 30 days", true(), "OK")')
    data_sources = {
        "ds_total": ds("Certificates", certs + " | stats count", time=False),
        "ds_expired": ds("Expired", certs + " | where days_left<0 | stats count", time=False),
        "ds_week": ds("Expiring within 7 days", certs + " | where days_left>=0 AND days_left<=7 | stats count",
                      time=False),
        "ds_month": ds("Expiring within 30 days", certs + " | where days_left>=0 AND days_left<=30 | stats count",
                       time=False),
        "ds_grades": ds(
            "Grades",
            certs + ' | eval Grade=coalesce(grade, "none") | stats count as Certificates by Grade'
            ' | eval order=case(Grade="A+",1, Grade="A",2, Grade="A-",3, Grade="B",4, Grade="C",5, Grade="D",6,'
            ' Grade="E",7, Grade="F",8, Grade="T",9, Grade="M",10, true(),11) | sort order'
            " | table Grade Certificates", time=False),
        "ds_issuers": ds("Issuers", certs + ' | eval Issuer=coalesce(issuer_o, issuer_cn, "unknown")'
                         " | stats count as Certificates by Issuer | sort - Certificates | head 10", time=False),
        "ds_expiry_timeline": ds(
            "Expiring in the next 90 days",
            certs + " | where days_left>=0 AND days_left<=90 | eval _time=strptime(not_after, \"%Y-%m-%dT%H:%M:%SZ\")"
            " | timechart span=1w count as Certificates", time=False),
        "ds_renew": ds(
            "Renew first",
            certs + " | where days_left<=30 | sort days_left" + expiry
            + ' | eval Expires=strftime(strptime(not_after, "%Y-%m-%dT%H:%M:%SZ"), "%Y-%m-%d"),'
            ' "Days left"=days_left | rename url AS URL, host AS Host, grade AS Grade, issuer_o AS Issuer'
            ' | table Expiry URL Host Expires "Days left" Grade Issuer', time=False),
        "ds_weak": ds(
            "Weak protocols and grades",
            certs + ' | where isnotnull(weak_protocols) OR grade IN ("F", "T", "M", "C", "D", "E")'
            ' | eval "Weak protocols"=mvjoin(weak_protocols, ", "), Problems=mvjoin(problems, "; ")'
            # Worst first: failing or untrusted, then weak protocols, then name mismatches (M).
            ' | eval order=case(grade IN ("F", "T"), 1, isnotnull(weak_protocols), 2, grade IN ("E", "D", "C"), 3,'
            ' true(), 4) | sort order URL'
            ' | rename url AS URL, grade AS Grade | table URL Grade "Weak protocols" Problems', time=False),
        "ds_orgs": ds_orgs,
    }
    visualizations = {
        "viz_total": single("Certificates", "ds_total"),
        "viz_expired": single("▲ Expired", "ds_expired", PROBLEM),
        "viz_week": single("▲ Expiring within 7 days", "ds_week", PROBLEM),
        "viz_month": single("■ Expiring within 30 days", "ds_month", WARNING),
        "viz_grades": bar("Grades", "ds_grades", kind="splunk.column"),
        "viz_issuers": bar("Top issuers", "ds_issuers"),
        "viz_expiry_timeline": bar("Expiring in the next 90 days", "ds_expiry_timeline", kind="splunk.column"),
        "viz_renew": asset_table("Renew first", "ds_renew", "URL", count=8,
                                 description="Expired and expiring within 30 days, soonest first."),
        "viz_weak": asset_table("Weak protocols and grades", "ds_weak", "URL", count=8,
                                description="Grade M means the certificate does not match the name; "
                                "T means it is not trusted."),
    }
    inputs = {"input_org": org}
    rows = [
        ("viz_total", 0, 0, 300, 110), ("viz_expired", 300, 0, 300, 110),
        ("viz_week", 600, 0, 300, 110), ("viz_month", 900, 0, 300, 110),
        ("viz_grades", 0, 110, 400, 300), ("viz_issuers", 400, 110, 400, 300),
        ("viz_expiry_timeline", 800, 110, 400, 300),
        ("viz_renew", 0, 410, 1200, 420),
        ("viz_weak", 0, 830, 1200, 420),
    ]
    dashboard("shadowtrackr_certificates", "Certificates",
              "TLS certificates on your internet-facing assets: expiry, grades, issuers and weak configurations.",
              "Certificates", inputs, data_sources, visualizations, rows)


# --- Search explorer --------------------------------------------------------------

# Checked against the live API. No commas or quotes: they go through makeresults csv.
EXAMPLES = [
    ("index=hosts problem=yes", "Hosts with a problem"),
    ("index=hosts remote_login_services=true", "Hosts with a remote login service such as SSH or RDP"),
    ("index=hosts by country", "Hosts per country"),
    ("index=websites https_status>=500", "Websites answering with a server error"),
    ("index=websites warning=yes earliest=-7d", "Websites with a warning seen in the last 7 days"),
    ("index=certificates by issuer earliest=-7d", "Certificates seen in the last 7 days per issuer"),
    ("index=certificates grade=T earliest=-7d", "Untrusted certificates"),
    ("index=dns rrtype=MX", "Mail (MX) records"),
    ("index=events earliest=-1d level>=80", "Problems and warnings of the last day"),
    ("index=events earliest=-1d by source", "Events of the last day per source"),
    ("index=suggestions", "Assets ShadowTrackr suggests adding to your monitoring"),
    ("index=emails", "Exposed email addresses"),
]


def explorer():
    for example in EXAMPLES:
        assert not any(c in "".join(example) for c in ',"'), "no commas or quotes in examples: {}".format(example)
    examples = "\n".join("{},{}".format(q, d) for q, d in EXAMPLES)
    data_sources = {
        "ds_results": ds("Query results", "| shadowtrackr query=$q|s$ account=$account|s$ max_results=$max$",
                         time=False),
        "ds_count": chain("Rows", "ds_results", "| stats count AS Rows"),
        "ds_examples": ds("Examples", '| makeresults format=csv data="Query,Shows\n' + examples + '"'
                          " | table Query Shows", time=False),
        "ds_accounts": ds("Accounts", "| rest splunk_server=local count=0"
                          " /servicesNS/nobody/shadowtrackr/configs/conf-shadowtrackr_account"
                          " | where title!=\"default\" | eval label=title, value=title | sort label"
                          " | table label value", time=False),
    }
    inputs = {
        "input_q": {"type": "input.text", "title": "Query",
                    "options": {"token": "q", "defaultValue": "index=hosts problem=yes"}},
        "input_account": {
            "type": "input.dropdown", "title": "Account", "dataSources": {"primary": "ds_accounts"},
            "options": {"token": "account", "selectFirstSearchResult": True,
                        "items": ">frame(label, value) | objects()"},
            "context": {"label": '>primary | seriesByName("label") | renameSeries("label") | formatByType(fmt)',
                        "value": '>primary | seriesByName("value") | renameSeries("value") | formatByType(fmt)',
                        "fmt": {"string": {}}},
        },
        "input_max": {"type": "input.dropdown", "title": "Max rows",
                      "options": {"token": "max", "defaultValue": "1000",
                                  "items": [{"label": "100", "value": "100"}, {"label": "1,000", "value": "1000"},
                                            {"label": "10,000", "value": "10000"}]}},
    }
    visualizations = {
        "viz_help": markdown(
            "Runs a live query against the ShadowTrackr API with `| shadowtrackr`, in the same language as the "
            "ShadowTrackr search box ([syntax](https://www.shadowtrackr.com/docs_v3/3-Search-and-Queries)). "
            "Type a query or click an example, then press **Submit**. Every submit is an API call. "
            "Needs a role with the list_storage_passwords capability (admin). "
            "Use **Open in Search** on the results to continue in SPL."),
        "viz_count": single("Rows", "ds_count"),
        "viz_results": table("Results", "ds_results", count=15),
        "viz_examples": {
            "type": "splunk.table", "title": "Examples", "description": "Click a row to use the query.",
            "dataSources": {"primary": "ds_examples"}, "options": {"count": 12},
            "eventHandlers": [{"type": "drilldown.setToken",
                               "options": {"tokens": [{"token": "q", "key": "row.Query.value"}]}}],
        },
    }
    rows = [
        ("viz_count", 0, 0, 300, 110), ("viz_help", 300, 0, 900, 110),
        ("viz_results", 0, 110, 1200, 560),
        ("viz_examples", 0, 670, 1200, 470),
    ]
    dashboard("shadowtrackr_explorer", "Search explorer",
              "Run live queries against the ShadowTrackr API.",
              "Search explorer", inputs, data_sources, visualizations, rows,
              layout_options={"submitButton": True, "submitOnDashboardLoad": False})


# --- Asset 360 ----------------------------------------------------------------------

# Rows of the inventory lookup whose field matches the asset or a related IP/hostname.
def related(lookup_name, *fields):
    terms = " OR ".join('[| `shadowtrackr_asset_terms($asset|s$)` | rename term AS {}]'.format(f) for f in fields)
    return "| inputlookup shadowtrackr_{} where st_present=1 | search {}".format(lookup_name, terms)


# One OR'd search string: several rows in a field named "search" would be ANDed.
TERMS = '[| `shadowtrackr_asset_terms($asset|s$)` | rename term AS search | format]'
SRC_DEST = ("eval Source=coalesce(src_ip, src), Destination=coalesce(dest_ip, dest, dest_host)")


def log_panel(macro, by, rename, extra=""):
    """Your own logs for the asset: one row per combination of the by fields, busiest first."""
    return ('`{macro}` {terms} | {src_dest} | fillnull value="-" {by}'
            " | stats count AS Events latest(_time) AS last{extra} by {by} | sort - Events | head 50"
            ' | eval Last=strftime(last, "%Y-%m-%d %H:%M") | fields - last | rename {rename}').format(
        macro=macro, terms=TERMS, src_dest=SRC_DEST, by=by, extra=extra, rename=rename)


def asset360():
    profile = "| makeresults | eval Asset=$asset|s$ | stenrich field=Asset"
    data_sources = {
        "ds_profile": ds("Profile", profile, time=False),
        "ds_status": chain("Status", "ds_profile",
                           '| eval Status=case(isnull(Asset) OR Asset="", "Enter an asset above", st_phishy=1, "▲ Phishy lookalike",'
                           ' st_known=1, "● Known asset", st_in_scope=1, "■ In scope, not found yet",'
                           ' isnull(st_known), "Not an IP or hostname", true(), "○ Not in your inventory")'
                           " | table Status"),
        "ds_ports": chain("Open ports", "ds_profile",
                          "| eval Ports=coalesce(mvcount(st_ports), 0) | table Ports"),
        "ds_cve_count": chain("CVEs", "ds_profile", "| eval CVEs=coalesce(st_cve_count, 0) | table CVEs"),
        "ds_findings_count": chain("Findings", "ds_profile",
                                   "| eval Findings=coalesce(mvcount(st_problems), 0)"
                                   "+coalesce(mvcount(st_warnings), 0) | table Findings"),
        "ds_details": chain(
            "Details", "ds_profile",
            '| eval Type=st_asset_type, "IP addresses"=st_ip, Hostnames=st_hostnames, Domain=st_domain,'
            ' Organization=st_organization, Country=st_country, Network=st_asn_name, Cloud=st_cloud_provider,'
            ' Software=st_software, "Website grade"=st_web_grade, "Certificate grade"=st_cert_grade,'
            ' "Certificate expires"=st_cert_expires, "Certificate issuer"=st_cert_issuer, Tags=st_tags,'
            ' "Lookalike of"=st_lookalike_of, "Lookalike score"=st_phishy_score,'
            ' "First seen"=st_first_seen, "Last seen"=st_last_seen'
            ' | table Type "IP addresses" Hostnames Domain Organization Country Network Cloud Software'
            ' "Website grade" "Certificate grade" "Certificate expires" "Certificate issuer" Tags "Lookalike of"'
            ' "Lookalike score" "First seen" "Last seen"'
            ' | foreach * [eval <<FIELD>>=mvjoin(\'<<FIELD>>\', ", ")]'
            ' | transpose 0 column_name=Field | rename "row 1" AS Value | where isnotnull(Value) AND Value!=""'),
        "ds_findings": chain(
            "Findings", "ds_profile",
            '| eval f=coalesce(mvappend(mvmap(st_problems, "▲ Problem|".st_problems),'
            ' mvmap(st_warnings, "■ Warning|".st_warnings)), "")'
            ' | mvexpand f | where f!="" | rex field=f "^(?<Status>[^|]+)\\|(?<Finding>.*)$"'
            " | table Status Finding"),
        "ds_services": chain(
            "Services", "ds_profile",
            '| eval s=coalesce(st_services, "") | mvexpand s | where s!=""'
            ' | rex field=s "^(?<Port>\\d+)/(?<Protocol>\\w+)\\s*(?<Service>.*)$" | eval Port=tonumber(Port)'
            " | sort Port | table Port Protocol Service"),
        "ds_websites": ds(
            "Websites", related("websites", "url", "host")
            + ' | eval Status=coalesce(https_status, http_status), Software=mvjoin(software, ", ")'
            " | sort url | rename url AS URL, title AS Title, grade AS Grade | table URL Status Grade Title Software",
            time=False),
        "ds_certificates": ds(
            "Certificates", related("certificates", "url", "host")
            + ' | eval days=floor((strptime(not_after, "%Y-%m-%dT%H:%M:%SZ")-now())/86400),'
            ' Expires=substr(not_after, 1, 10), "Days left"=days, Issuer=coalesce(issuer_o, issuer_cn)'
            " | sort days | rename url AS URL, grade AS Grade | table URL Grade Expires \"Days left\" Issuer",
            time=False),
        "ds_cves": ds(
            "CVEs", related("cves", "asset")
            + ' | eval Flags=trim(if(exploited=1, "⚠ Exploited ", "").if(cisa_kev=1, "◆ CISA KEV", ""))'
            " | sort - exploited - cvss | rename cve AS CVE, cvss AS CVSS, software AS Software, asset AS Asset"
            " | table CVE CVSS Flags Software Asset", time=False),
        "ds_dns": ds(
            "DNS records", related("dns", "url")
            + " | sort url rrtype | rename url AS Name, rrtype AS Type, rrdata AS Value | table Name Type Value",
            time=False),
        # Chained searches only see the fields a raw event search names explicitly.
        "ds_events": ds("ShadowTrackr events", "`shadowtrackr_events` " + TERMS
                        + " | fields _time level signature message"),
        "ds_event_timeline": chain(
            "Events over time", "ds_events",
            '| eval Status=case(level>=90, "Problems", level>=80, "Warnings", true(), "Info")'
            " | timechart count by Status | fillnull value=0 Problems Warnings Info"
            " | table _time Problems Warnings Info"),
        "ds_event_list": chain(
            "Latest events", "ds_events",
            "| sort - _time | head 100 | " + STATUS_LABEL + ' | eval Time=strftime(_time, "%Y-%m-%d %H:%M")'
            " | rename signature AS Event, message AS Details | table Time Status Event Details"),
        "ds_log_activity": ds(
            "Activity in your logs",
            "(`shadowtrackr_asset_network`) OR (`shadowtrackr_asset_web`) OR (`shadowtrackr_asset_auth`)"
            " OR (`shadowtrackr_asset_ids`) " + TERMS
            + ' | eval Source=case(isnotnull(mvfind(tag, "^attack$")), "IDS/IPS",'
            ' isnotnull(mvfind(tag, "^authentication$")), "Authentication",'
            ' isnotnull(mvfind(tag, "^web$")), "Web/proxy/WAF", true(), "Network")'
            " | timechart count by Source"),
        "ds_network": ds("Network traffic", log_panel(
            "shadowtrackr_asset_network", "Source Destination dest_port", "dest_port AS Port",
            extra=" values(action) AS Action")),
        "ds_web": ds("Web, proxy and WAF", log_panel(
            "shadowtrackr_asset_web", "Source http_method url status action",
            "http_method AS Method, url AS URL, status AS Status, action AS Action")),
        "ds_auth": ds("Authentication", log_panel(
            "shadowtrackr_asset_auth", "user Source Destination app action",
            "user AS User, app AS App, action AS Result")),
        "ds_ids": ds("IDS/IPS", log_panel(
            "shadowtrackr_asset_ids", "signature severity Source Destination action",
            "signature AS Signature, severity AS Severity, action AS Action")),
    }

    inputs = {
        "input_asset": {"type": "input.text", "title": "Asset (IP, hostname or URL)",
                        "options": {"token": "asset", "defaultValue": ""}},
        "input_time": dict(TIME_INPUT, title="Time range (events and logs)"),
    }
    visualizations = {
        "viz_intro": markdown(
            "Everything about one asset: ShadowTrackr's view from the inventory lookups and events, and your own "
            "logs for the asset and its related IPs and hostnames. Open it from any asset in the other dashboards. "
            "The log panels use the `shadowtrackr_asset_network`, `_web`, `_auth` and `_ids` macros (CIM tags by "
            "default); point them at your indexes under Settings > Advanced search > Search macros."),
        "viz_status": single("Status", "ds_status"),
        "viz_ports": single("Open ports", "ds_ports"),
        "viz_cve_count": single("CVEs", "ds_cve_count", PROBLEM),
        "viz_findings_count": single("Problems and warnings", "ds_findings_count", WARNING),
        "viz_details": table("Details", "ds_details", count=18),
        "viz_findings": table("Problems and warnings", "ds_findings", count=10),
        "viz_services": table("Services", "ds_services", count=10),
        "viz_websites": asset_table("Websites", "ds_websites", "URL", count=8),
        "viz_certificates": table("Certificates", "ds_certificates", count=8),
        "viz_cves": table("CVEs", "ds_cves", count=8, description="Click a row to open the CVE at NVD.",
                          url="https://nvd.nist.gov/vuln/detail/$row.CVE.value$"),
        "viz_dns": table("DNS records", "ds_dns", count=8),
        "viz_event_timeline": {
            "type": "splunk.column", "title": "ShadowTrackr events", "dataSources": {"primary": "ds_event_timeline"},
            "options": {"stackMode": "stacked", "legendDisplay": "top",
                        "seriesColorsByField": {"Problems": PROBLEM, "Warnings": WARNING, "Info": INFO},
                        "xAxisTitleVisibility": "hide", "yAxisTitleVisibility": "hide"},
        },
        "viz_event_list": table("Latest ShadowTrackr events", "ds_event_list", count=8),
        "viz_logs_title": markdown("### Your logs for this asset"),
        "viz_log_activity": {
            "type": "splunk.column", "title": "Activity in your logs", "dataSources": {"primary": "ds_log_activity"},
            "options": {"stackMode": "stacked", "legendDisplay": "top",
                        "xAxisTitleVisibility": "hide", "yAxisTitleVisibility": "hide"},
        },
        "viz_network": table("Network traffic (firewall)", "ds_network", count=8),
        "viz_web": table("Web, proxy and WAF", "ds_web", count=8),
        "viz_auth": table("Authentication", "ds_auth", count=8),
        "viz_ids": table("IDS/IPS", "ds_ids", count=8),
    }
    rows = [
        ("viz_intro", 0, 0, 1200, 70),
        ("viz_status", 0, 70, 300, 110), ("viz_ports", 300, 70, 300, 110),
        ("viz_cve_count", 600, 70, 300, 110), ("viz_findings_count", 900, 70, 300, 110),
        ("viz_details", 0, 180, 500, 520), ("viz_findings", 500, 180, 700, 260),
        ("viz_services", 500, 440, 700, 260),
        ("viz_websites", 0, 700, 600, 330), ("viz_certificates", 600, 700, 600, 330),
        ("viz_cves", 0, 1030, 600, 330), ("viz_dns", 600, 1030, 600, 330),
        ("viz_event_timeline", 0, 1360, 500, 330), ("viz_event_list", 500, 1360, 700, 330),
        ("viz_logs_title", 0, 1690, 1200, 50),
        ("viz_log_activity", 0, 1740, 1200, 260),
        ("viz_network", 0, 2000, 600, 360), ("viz_web", 600, 2000, 600, 360),
        ("viz_auth", 0, 2360, 600, 360), ("viz_ids", 600, 2360, 600, 360),
    ]
    dashboard("shadowtrackr_asset", "Asset 360",
              "One asset from every angle: ShadowTrackr's inventory, findings and events, and your own logs.",
              "Asset 360", inputs, data_sources, visualizations, rows)


if __name__ == "__main__":
    overview()
    vulnerabilities()
    certificates()
    explorer()
    asset360()
