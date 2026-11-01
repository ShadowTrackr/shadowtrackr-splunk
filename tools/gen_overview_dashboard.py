#!/usr/bin/env python3
"""Generate the Dashboard Studio Overview (package/default/data/ui/views).

Usage: python3 -I tools/gen_overview_dashboard.py package/default/data/ui/views/shadowtrackr_overview.xml
"""

import json
import sys

# Organization filter: "*" matches everything, including events from older
# API versions that have no organization.
BASE = '`shadowtrackr_events` | where "$org$"="*" OR vendor_account="$org$"'
ALERTS = BASE + " | where level>=$min_level$"


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
    "ds_timeline": ds("Events over time", BASE + " | timechart count by st_status"),
    "ds_category": ds("Events by category", BASE + ' | eval st_category=coalesce(st_category, "unclassified") | stats count by st_category | sort - count'),
    "ds_latest": ds(
        "Latest alerts",
        ALERTS + ' | sort - _time | head 100 | eval time=strftime(_time, "%Y-%m-%d %H:%M:%S")'
        " | table time severity vendor_account st_category dest message",
    ),
    "ds_top_assets": ds(
        "Assets with most alerts",
        ALERTS + " | stats count as events max(level) as max_level latest(message) as latest_message by dest"
        " | sort - max_level - events | head 20",
    ),
    "ds_changes": ds("Changes by type", BASE + " | search eventtype=shadowtrackr_change | stats count by signature | sort - count | head 10"),
    "ds_unclassified": ds(
        "Unclassified event types",
        BASE + " | search NOT signature=* | stats count latest(message) as example_message by eventid category | sort - count",
    ),
    "ds_orgs": {
        "type": "ds.search",
        "name": "Organizations",
        "options": {
            "query": "`shadowtrackr_events` vendor_account=* | stats count by vendor_account | sort vendor_account",
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


visualizations = {
    "viz_total": single("Events", "ds_total"),
    "viz_problems": single("Problems (level 90+)", "ds_problems", "#DC4E41"),
    "viz_warnings": single("Warnings (level 80-89)", "ds_warnings", "#F1813F"),
    "viz_assets": single("Assets with events", "ds_assets"),
    "viz_timeline": {
        "type": "splunk.column", "title": "Events over time by status", "dataSources": {"primary": "ds_timeline"},
        "options": {"stackMode": "stacked",
                    "seriesColorsByField": {"problem": "#DC4E41", "warning": "#F1813F", "info": "#7B56DB"}},
    },
    "viz_category": {"type": "splunk.bar", "title": "Events by category", "dataSources": {"primary": "ds_category"},
                     "options": {"legendDisplay": "off"}},
    "viz_latest": {"type": "splunk.table", "title": "Latest alerts", "dataSources": {"primary": "ds_latest"},
                   "description": "Problems only, or problems and warnings, depending on the Alerts filter.",
                   "options": {"count": 10}},
    "viz_top_assets": {"type": "splunk.table", "title": "Assets with the most alerts",
                       "dataSources": {"primary": "ds_top_assets"}, "options": {"count": 10}},
    "viz_changes": {"type": "splunk.bar", "title": "Top changes", "dataSources": {"primary": "ds_changes"},
                    "options": {"legendDisplay": "off"}},
    "viz_unclassified": {
        "type": "splunk.table", "title": "Event types without a classification",
        "description": "Normally empty: the app refreshes the event type catalogue from the API daily.",
        "dataSources": {"primary": "ds_unclassified"}, "options": {"count": 5},
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
        "options": {
            "token": "org", "defaultValue": "*",
            "items": ">frame(label, value) | prepend(formattedStatics) | objects()",
        },
        "context": {
            "formattedConfig": {"number": {"prefix": ""}},
            "formattedStatics": ">statics | formatByType(formattedConfig)",
            "statics": [["All"], ["*"]],
            "label": '>primary | seriesByName("vendor_account") | renameSeries("label") | formatByType(formattedConfig)',
            "value": '>primary | seriesByName("vendor_account") | renameSeries("value") | formatByType(formattedConfig)',
        },
    },
}

layout = [
    ("viz_total", 0, 0, 300, 110), ("viz_problems", 300, 0, 300, 110),
    ("viz_warnings", 600, 0, 300, 110), ("viz_assets", 900, 0, 300, 110),
    ("viz_timeline", 0, 110, 800, 320), ("viz_category", 800, 110, 400, 320),
    ("viz_latest", 0, 430, 1200, 400),
    ("viz_top_assets", 0, 830, 700, 400), ("viz_changes", 700, 830, 500, 400),
    ("viz_unclassified", 0, 1230, 1200, 250),
]

definition = {
    "title": "ShadowTrackr Overview",
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
