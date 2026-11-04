#!/usr/bin/env python3
"""Generate soc-triage-dashboard.ndjson: saved objects for the Wazuh dashboard.

The Wazuh dashboard is built on OpenSearch Dashboards, which imports saved objects
(index pattern, visualisations, saved search, dashboard) from an NDJSON file.
Visualisation definitions are JSON strings inside JSON, so they are built here in
Python rather than written by hand.

    python3 dashboard/build_dashboard.py            # rewrites dashboard/soc-triage-dashboard.ndjson
"""
import json
from pathlib import Path

INDEX = "soc-triage-incidents"
PATTERN_ID = "soc-triage-incidents"
OUT = Path(__file__).with_name("soc-triage-dashboard.ndjson")

SEARCH_SOURCE = json.dumps({
    "query": {"query": "", "language": "kuery"}, "filter": [],
    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
})


def count(agg_id="1"):
    return {"id": agg_id, "enabled": True, "type": "count", "schema": "metric", "params": {}}


def terms(agg_id, field, schema, size=10, order_by="1"):
    return {"id": agg_id, "enabled": True, "type": "terms", "schema": schema,
            "params": {"field": field, "size": size, "order": "desc", "orderBy": order_by,
                       "otherBucket": False, "missingBucket": False}}


def visualization(vis_id, title, vis_type, aggs, params, query=""):
    source = json.loads(SEARCH_SOURCE)
    source["query"]["query"] = query
    return {
        "id": vis_id,
        "type": "visualization",
        "attributes": {
            "title": title,
            "visState": json.dumps({"title": title, "type": vis_type, "aggs": aggs, "params": params}),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(source)},
        },
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern", "id": PATTERN_ID}],
        "migrationVersion": {"visualization": "7.10.0"},
    }


PIE_PARAMS = {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
              "isDonut": True, "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}}

TABLE_PARAMS = {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
                "showTotal": False, "totalFunc": "sum", "percentageCol": ""}


def metric_params(font=40):
    return {"addTooltip": True, "addLegend": False, "type": "metric",
            "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                       "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 10000}],
                       "labels": {"show": True}, "invertColors": False,
                       "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                                 "subText": "", "fontSize": font}}}


HISTOGRAM_PARAMS = {
    "type": "histogram", "grid": {"categoryLines": False},
    "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True,
                      "style": {}, "scale": {"type": "linear"},
                      "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
    "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left",
                   "show": True, "style": {}, "scale": {"type": "linear", "mode": "normal"},
                   "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                   "title": {"text": "Incidents"}}],
    "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                      "data": {"label": "Incidents", "id": "1"}, "valueAxis": "ValueAxis-1",
                      "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}],
    "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [],
    "addTimeMarker": False, "labels": {"show": False},
    "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"},
}

objects = [
    {
        "id": PATTERN_ID,
        "type": "index-pattern",
        "attributes": {"title": f"{INDEX}*", "timeFieldName": "@timestamp"},
        "references": [],
        "migrationVersion": {"index-pattern": "7.6.0"},
    },
    visualization("soc-triage-vis-totals", "SOC Triage - Totals", "metric",
                  [count(), {"id": "2", "enabled": True, "type": "avg", "schema": "metric",
                             "params": {"field": "final_score", "customLabel": "Average risk score"}}],
                  metric_params()),
    visualization("soc-triage-vis-over-time", "SOC Triage - Incidents over time by severity", "histogram",
                  [count(),
                   {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
                    "params": {"field": "@timestamp", "useNormalizedOpenSearchInterval": True,
                               "interval": "auto", "drop_partials": False, "min_doc_count": 1,
                               "extended_bounds": {}}},
                   terms("3", "severity", "group", size=4)],
                  HISTOGRAM_PARAMS),
    visualization("soc-triage-vis-severity", "SOC Triage - Severity breakdown", "pie",
                  [count(), terms("2", "severity", "segment", size=4)], PIE_PARAMS),
    visualization("soc-triage-vis-category", "SOC Triage - Incidents by category", "pie",
                  [count(), terms("2", "category_label", "segment", size=8)], PIE_PARAMS),
    visualization("soc-triage-vis-sources", "SOC Triage - Top source IPs", "table",
                  [count(),
                   {"id": "3", "enabled": True, "type": "max", "schema": "metric",
                    "params": {"field": "final_score", "customLabel": "Highest score"}},
                   terms("2", "src_ip", "bucket", size=10)],
                  TABLE_PARAMS),
    visualization("soc-triage-vis-hosts", "SOC Triage - Targeted hosts", "table",
                  [count(), terms("2", "agent_name", "bucket", size=10)], TABLE_PARAMS),
    visualization("soc-triage-vis-injection", "SOC Triage - Prompt-injection attempts", "metric",
                  [count()], metric_params(), query="injection_detected:true"),
    visualization("soc-triage-vis-ai", "SOC Triage - AI analysis source", "table",
                  [count(),
                   {"id": "3", "enabled": True, "type": "avg", "schema": "metric",
                    "params": {"field": "ai_adjustment_applied", "customLabel": "Avg AI points added"}},
                   terms("2", "ai_source", "bucket", size=10)],
                  TABLE_PARAMS),
    {
        "id": "soc-triage-search-incidents",
        "type": "search",
        "attributes": {
            "title": "SOC Triage - Incident list",
            "description": "",
            "hits": 0,
            "columns": ["severity", "final_score", "category_label", "src_ip", "agent_name",
                        "ticket_url", "incident_id"],
            "sort": [["@timestamp", "desc"]],
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                **json.loads(SEARCH_SOURCE), "highlightAll": True, "version": True})},
        },
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern", "id": PATTERN_ID}],
        "migrationVersion": {"search": "7.9.3"},
    },
]

# Dashboard layout: 48-column grid
LAYOUT = [
    ("soc-triage-vis-totals", "visualization", 0, 0, 24, 8),
    ("soc-triage-vis-injection", "visualization", 24, 0, 24, 8),
    ("soc-triage-vis-over-time", "visualization", 0, 8, 32, 14),
    ("soc-triage-vis-severity", "visualization", 32, 8, 16, 14),
    ("soc-triage-vis-sources", "visualization", 0, 22, 16, 14),
    ("soc-triage-vis-hosts", "visualization", 16, 22, 16, 14),
    ("soc-triage-vis-category", "visualization", 32, 22, 16, 14),
    ("soc-triage-vis-ai", "visualization", 0, 36, 16, 12),
    ("soc-triage-search-incidents", "search", 16, 36, 32, 20),
]

panels, references = [], []
for n, (obj_id, obj_type, x, y, w, h) in enumerate(LAYOUT):
    panels.append({"version": "2.0.0", "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(n + 1)},
                   "panelIndex": str(n + 1), "embeddableConfig": {}, "panelRefName": f"panel_{n}"})
    references.append({"name": f"panel_{n}", "type": obj_type, "id": obj_id})

objects.append({
    "id": "soc-triage-dashboard",
    "type": "dashboard",
    "attributes": {
        "title": "SOC Triage Bot",
        "hits": 0,
        "description": "Incidents triaged by the SOC triage bot",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
        "version": 1,
        "timeRestore": True,
        "timeFrom": "now-7d",
        "timeTo": "now",
        "refreshInterval": {"pause": False, "value": 60000},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
            {"query": {"query": "", "language": "kuery"}, "filter": []})},
    },
    "references": references,
    "migrationVersion": {"dashboard": "7.9.3"},
})

if __name__ == "__main__":
    OUT.write_text("".join(json.dumps(o, separators=(",", ":")) + "\n" for o in objects), encoding="utf-8")
    print(f"Wrote {len(objects)} saved objects to {OUT}")
