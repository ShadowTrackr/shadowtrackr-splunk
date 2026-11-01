#!/usr/bin/env python3
"""Generate the Dashboard Studio Overview (package/default/data/ui/views).

Usage: python3 -I tools/gen_overview_dashboard.py package/default/data/ui/views/shadowtrackr_overview.xml
"""

import json
import sys

# Status colours, validated for the dark surface (#171d21) with the dataviz
# palette validator: lightness band, CVD separation and 3:1 contrast all pass.
PROBLEM = "#d03b3b"
WARNING = "#c98500"
INFO = "#3987e5"

# Organization filter: "*" matches everything, including events without an
# organization (normal, non-group API keys).
BASE = '`shadowtrackr_events` | where "$org$"="*" OR vendor_account="$org$"'
ALERTS = BASE + " | where level>=$min_level$"

# Status shown as icon + label, so it never relies on colour alone.
STATUS_LABEL = 'eval Status=case(level>=90, "▲ Problem", level>=80, "■ Warning", true(), "● Info")'

HEADER_MARKDOWN = (
    "## ShadowTrackr\n"
    "External attack surface monitoring · "
    "[Open ShadowTrackr](https://shadowtrackr.com/usr/) · "
    "[Documentation](https://shadowtrackr.com/docs)"
)


def ds(name, query):
    return {
        "type": "ds.search",
        "name": name,
        "options": {"query": query, "queryParameters": {"earliest": "$global_time.earliest$", "latest": "$global_time.latest$"}},
    }


data_sources = {
    "ds_total": ds("Total events", BASE + " | stats count"),
    "ds_problems": ds("Problems", BASE + " | where level>=90 | stats count"),
    "ds_warnings": ds("Warnings", BASE + " | where level>=80 AND level<90 | stats count"),
    "ds_assets": ds("Assets with events", BASE + " | stats dc(dest) as assets"),
    "ds_timeline": ds(
        "Events over time",
        BASE + ' | eval Status=case(level>=90, "Problems", level>=80, "Warnings", true(), "Info")'
        " | timechart count by Status | fillnull value=0 Problems Warnings Info"
        " | table _time Problems Warnings Info",
    ),
    "ds_category": ds(
        "Events by category",
        BASE + ' | eval Category=coalesce(st_category, "unclassified") | stats count as Events by Category | sort - Events',
    ),
    "ds_latest": ds(
        "Latest alerts",
        ALERTS + " | sort - _time | head 100 | " + STATUS_LABEL
        + ' | eval Time=strftime(_time, "%Y-%m-%d %H:%M")'
        " | rename dest AS Asset, signature AS Alert"
        " | table Time Status Asset Alert",
    ),
    "ds_top_assets": ds(
        "Assets with most alerts",
        ALERTS + " | stats count as Alerts max(level) as level latest(signature) as \"Latest alert\" by dest"
        " | sort - level - Alerts | head 20 | " + STATUS_LABEL
        + ' | rename dest AS Asset | table Asset Status Alerts "Latest alert"',
    ),
    "ds_changes": ds(
        "Changes by type",
        BASE + " | search eventtype=shadowtrackr_change | stats count as Changes by signature"
        " | rename signature AS Change | sort - Changes | head 10",
    ),
    "ds_unclassified": ds(
        "Unclassified event types",
        BASE + " | search NOT signature=* | stats count as Events latest(message) as Example by eventid category"
        " | rename eventid AS \"Event id\", category AS Source | sort - Events",
    ),
    # Always returns an "All organizations" row, so the dropdown never shows
    # an empty-results warning for normal (single-organization) API keys.
    "ds_orgs": {
        "type": "ds.search",
        "name": "Organizations",
        "options": {
            "query": "`shadowtrackr_events` vendor_account=* | stats count by vendor_account"
                     " | eval label=vendor_account, value=vendor_account, order=1"
                     ' | append [| makeresults | eval label="All organizations", value="*", order=0]'
                     " | sort order label | table label value",
            "queryParameters": {"earliest": "-30d", "latest": "now"},
        },
    },
}


def single(title, ds_id, color=None):
    viz = {"type": "splunk.singlevalue", "title": title, "dataSources": {"primary": ds_id},
           "options": {"sparklineDisplay": "off"}}
    if color:
        viz["options"]["majorColor"] = color
    return viz


def bar(title, ds_id):
    return {
        "type": "splunk.bar", "title": title, "dataSources": {"primary": ds_id},
        "options": {"legendDisplay": "off", "seriesColors": [INFO], "dataValuesDisplay": "all",
                    "xAxisTitleVisibility": "hide", "yAxisTitleVisibility": "hide"},
    }


visualizations = {
    "viz_logo": {
        "type": "splunk.image",
        "options": {"src": "/static/app/shadowtrackr/images/logo_tile.png", "preserveAspectRatio": True},
        "eventHandlers": [{"type": "drilldown.customUrl",
                           "options": {"url": "https://shadowtrackr.com/usr/", "newTab": True}}],
    },
    "viz_title": {"type": "splunk.markdown", "options": {"markdown": HEADER_MARKDOWN}},
    "viz_total": single("Events", "ds_total"),
    "viz_problems": single("▲ Problems (level 90+)", "ds_problems", PROBLEM),
    "viz_warnings": single("■ Warnings (level 80-89)", "ds_warnings", WARNING),
    "viz_assets": single("Assets with events", "ds_assets"),
    "viz_timeline": {
        "type": "splunk.column", "title": "Events over time", "dataSources": {"primary": "ds_timeline"},
        "options": {"stackMode": "stacked", "legendDisplay": "top",
                    "seriesColorsByField": {"Problems": PROBLEM, "Warnings": WARNING, "Info": INFO},
                    "xAxisTitleVisibility": "hide", "yAxisTitleVisibility": "hide"},
    },
    "viz_category": bar("Events by category", "ds_category"),
    "viz_latest": {
        "type": "splunk.table", "title": "Latest alerts", "dataSources": {"primary": "ds_latest"},
        "description": "Problems only, or problems and warnings, depending on the Alerts filter. Click a row to see the event.",
        "options": {"count": 10},
    },
    "viz_top_assets": {
        "type": "splunk.table", "title": "Assets with the most alerts", "dataSources": {"primary": "ds_top_assets"},
        "options": {"count": 9},
    },
    "viz_changes": {
        "type": "splunk.table", "title": "Top changes", "dataSources": {"primary": "ds_changes"},
        "options": {"count": 10},
    },
    # Only shown when the catalogue misses an event type.
    "viz_unclassified": {
        "type": "splunk.table", "title": "Event types without a classification",
        "description": "The app refreshes the event type catalogue from the API daily; types listed here are not in it yet.",
        "dataSources": {"primary": "ds_unclassified"}, "options": {"count": 5}, "hideWhenNoData": True,
    },
}

inputs = {
    "input_time": {"type": "input.timerange", "title": "Time range",
                   "options": {"token": "global_time", "defaultValue": "-7d@h,now"}},
    "input_level": {
        "type": "input.dropdown", "title": "Alerts",
        "options": {"token": "min_level", "defaultValue": "90",
                    "items": [{"label": "Problems only (90+)", "value": "90"},
                              {"label": "Problems and warnings (80+)", "value": "80"}]},
    },
    "input_org": {
        "type": "input.dropdown", "title": "Organization",
        "dataSources": {"primary": "ds_orgs"},
        "options": {"token": "org", "defaultValue": "*", "items": ">frame(label, value) | objects()"},
        "context": {
            "label": '>primary | seriesByName("label") | renameSeries("label") | formatByType(formattedConfig)',
            "value": '>primary | seriesByName("value") | renameSeries("value") | formatByType(formattedConfig)',
            "formattedConfig": {"number": {"prefix": ""}},
        },
    },
}

HEADER = 90
layout = [("viz_logo", 0, 0, 90, HEADER), ("viz_title", 90, 0, 1110, HEADER)] + [
    (item, x, y + HEADER, w, h) for item, x, y, w, h in [
        ("viz_total", 0, 0, 300, 110), ("viz_problems", 300, 0, 300, 110),
        ("viz_warnings", 600, 0, 300, 110), ("viz_assets", 900, 0, 300, 110),
        ("viz_timeline", 0, 110, 800, 320), ("viz_category", 800, 110, 400, 320),
        ("viz_latest", 0, 430, 1200, 400),
        ("viz_top_assets", 0, 830, 760, 440), ("viz_changes", 760, 830, 440, 440),
        ("viz_unclassified", 0, 1270, 1200, 250),
    ]
]

definition = {
    "title": "Overview",
    "description": "Events from your external attack surface, collected by the ShadowTrackr events input.",
    "inputs": inputs,
    "defaults": {},
    "visualizations": visualizations,
    "dataSources": data_sources,
    "layout": {
        "type": "grid",
        "options": {"width": 1200},
        "globalInputs": ["input_time", "input_level", "input_org"],
        "structure": [{"item": i, "type": "block", "position": {"x": x, "y": y, "w": w, "h": h}}
                      for i, x, y, w, h in layout],
    },
}

XML = """<dashboard version="2" theme="dark">
    <label>Overview</label>
    <description>Events from your external attack surface, collected by the ShadowTrackr events input.</description>
    <definition><![CDATA[
%s
    ]]></definition>
    <meta type="hiddenElements"><![CDATA[
{
    "hideEdit": false,
    "hideOpenInSearch": false,
    "hideExport": false
}
    ]]></meta>
</dashboard>
"""

if __name__ == "__main__":
    with open(sys.argv[1], "w", encoding="utf-8") as f:
        f.write(XML % json.dumps(definition, indent=4))
