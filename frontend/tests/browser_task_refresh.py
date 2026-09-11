"""Regress task queries against running frontend and real local analysis backend.

Requires Python Playwright and its Chromium browser. This script POSTs uniquely named,
explicitly synthetic tasks to the supplied backend. It does not start services, change
their source, or validate any pre-existing real task. HTTP 503 and delayed responses
are injected only in this browser to exercise failure and stale-response handling.
"""

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

from playwright.sync_api import expect, sync_playwright


def make_events(task_id, start=0, count=10, destination="198.51.100.20"):
    base = datetime(2026, 9, 10, 20, 0, tzinfo=timezone(timedelta(hours=8)))
    return [
        {
            "schema_version": "1.0", "event_id": f"evt_{task_id.removeprefix('task_')}_{i:03}",
            "task_id": task_id, "timestamp": (base + timedelta(minutes=i)).isoformat(),
            "source_type": "network_flow", "source": "zeek", "host_id": "firewall01",
            "src_ip": "10.10.2.50", "src_port": 45000 + i,
            "dst_ip": destination, "dst_port": 443, "action": "network_connect",
            "network": {"protocol": "tcp", "direction": "outbound", "bytes_in": 120,
                        "bytes_out": 180, "session_id": f"synthetic_{task_id}_{i:03}"},
            "raw_event": {"synthetic": True, "test_case": "frontend_refresh_browser",
                          "orig_bytes": 180, "resp_bytes": 120},
            "labels": ["synthetic", "beacon_candidate"], "metadata": {"synthetic": True},
        }
        for i in range(start, start + count)
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:5173")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory for report, API snapshots, and screenshots")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    api_url = args.api_url.rstrip("/")
    run_id = uuid4().hex[:12]
    task_a = f"task_refresh_browser_{run_id}_a"
    task_b = f"task_refresh_browser_{run_id}_b"
    report = {"scope": "Synthetic inputs through real backend pipeline; not real-task acceptance",
              "tasks": [task_a, task_b], "checks": [], "page_errors": [], "console": []}

    def check(name, condition, detail=None):
        report["checks"].append({"name": name, "passed": bool(condition), "detail": detail})
        print(f"{'PASS' if condition else 'FAIL'} {name}", flush=True)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        page.set_default_timeout(10000)
        page.on("pageerror", lambda error: report["page_errors"].append(str(error)))
        page.on("console", lambda message: report["console"].append({"type": message.type, "text": message.text}))
        request_paths = []
        response_paths = []
        page.on("request", lambda request: request_paths.append(urlparse(request.url).path) if "/api/" in request.url else None)
        page.on("response", lambda response: response_paths.append(urlparse(response.url).path) if "/api/" in response.url else None)

        def api(path):
            response = page.request.get(api_url + path)
            assert response.ok, f"Backend GET {path}: HTTP {response.status}"
            return response.json()["data"]

        def ingest(task_id, start=0, count=10, destination="198.51.100.20"):
            rows = make_events(task_id, start, count, destination)
            response = page.request.post(api_url + "/api/events", data=rows)
            assert response.ok, f"Backend ingest failed: HTTP {response.status}: {response.text()}"
            assert response.json()["data"]["accepted"] == count
            (args.output_dir / f"{task_id}-input-{start}.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")

        def snapshot(task_id):
            data = {"events": [e for e in api("/api/events") if e["task_id"] == task_id],
                    "alerts": [a for a in api("/api/alerts") if a["task_id"] == task_id],
                    "graph": api(f"/api/attack-graph/{task_id}"), "trace": api(f"/api/trace/{task_id}"),
                    "task": api(f"/api/tasks/{task_id}")}
            (args.output_dir / f"{task_id}-api.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            return data

        def metric(label):
            return page.locator(".metric-card").filter(has_text=label).locator("strong").inner_text()

        def query(task_id, name, wait=True):
            page.locator("#task-id").fill(task_id)
            start = len(request_paths)
            response_start = len(response_paths)
            if not wait:
                page.get_by_role("button", name="加载任务", exact=True).click()
                return
            with page.expect_response(lambda response: urlparse(response.url).path == f"/api/tasks/{task_id}"):
                page.get_by_role("button", name="加载任务", exact=True).click()
            wanted = {"/api/events", "/api/alerts", f"/api/tasks/{task_id}",
                      f"/api/attack-graph/{task_id}", f"/api/trace/{task_id}"}
            for _ in range(500):
                if wanted.issubset(set(response_paths[response_start:])):
                    break
                page.wait_for_timeout(20)
            expect(page.locator(".metric-card").filter(has_text="…")).to_have_count(0)
            check(name + "_requests_all_five_endpoints", wanted.issubset(set(request_paths[start:])), request_paths[start:])

        def counts(name, expected):
            check(name, metric("标准化事件") == str(len(expected["events"])) and
                  metric("检测告警") == str(len(expected["alerts"])),
                  {"ui_events": metric("标准化事件"), "ui_alerts": metric("检测告警"),
                   "api_events": len(expected["events"]), "api_alerts": len(expected["alerts"])})

        try:
            page.goto(args.base_url)
            page.wait_for_load_state("networkidle")
            (args.output_dir / "initial-page.txt").write_text(page.locator("body").inner_text(), encoding="utf-8")
            # Ingest only after the app has loaded its first list responses.
            ingest(task_a)
            first = snapshot(task_a)
            check("real_pipeline_detects_synthetic_beacon", len(first["events"]) == 10 and
                  any(alert["rule_id"] == "NET-BEACON" for alert in first["alerts"]))
            query(task_a, "new_task_query")
            counts("new_task_query_matches_api_without_refresh", first)
            page.screenshot(path=str(args.output_dir / "query-after-ingest.png"), full_page=True)
            page.get_by_role("button", name="事件流", exact=True).click()
            check("new_task_events_table_has_ten_rows", page.locator(".events-table tbody tr").count() == 10)
            page.get_by_role("button", name="检测告警", exact=True).click()
            check("new_task_alert_cards_match_api", page.locator(".alert-card").count() == len(first["alerts"]))
            ingest(task_a, start=10, count=5)
            query(task_a, "same_task_query")
            latest_a = snapshot(task_a)
            counts("same_task_query_reads_fifteen_events", latest_a)
            page.screenshot(path=str(args.output_dir / "same-task-after-append.png"), full_page=True)

            ingest(task_b, count=4, destination="198.51.100.21")
            initial_b = snapshot(task_b)
            query(task_b, "switch_to_b")
            counts("task_switch_isolated_counts", initial_b)
            page.get_by_role("button", name="事件流", exact=True).click()
            ids = page.locator(".event-detail-button").evaluate_all("buttons => buttons.map(button => button.getAttribute('aria-label'))")
            check("task_switch_events_do_not_contain_other_task", len(ids) == 4 and all(task_b.removeprefix("task_") in value for value in ids), ids)
            query(task_a, "switch_back_to_a")
            counts("switch_back_to_a_matches_api", latest_a)

            # Hold actual A responses. B gains data after these responses were fetched,
            # so late A list responses would visibly regress B from ten events to four.
            held = []
            held_paths = set()
            targets = {"/api/events", "/api/alerts", f"/api/tasks/{task_a}",
                       f"/api/attack-graph/{task_a}", f"/api/trace/{task_a}"}

            def delay_a(route):
                path = urlparse(route.request.url).path
                if path in targets and path not in held_paths:
                    held_paths.add(path)
                    held.append((route, route.fetch()))
                else:
                    route.continue_()

            page.route("**/api/**", delay_a)
            query(task_a, "delayed_a", wait=False)
            for _ in range(100):
                if len(held) == 5:
                    break
                page.wait_for_timeout(20)
            check("race_holds_five_actual_a_responses", len(held) == 5, sorted(held_paths))
            check("loading_lists_show_pending_not_zero", metric("标准化事件") == "…" and metric("检测告警") == "…")
            ingest(task_b, start=4, count=6, destination="198.51.100.21")
            latest_b = snapshot(task_b)
            query(task_b, "race_newer_b_query")
            counts("race_newer_b_initially_matches_api", latest_b)
            for route, response in held:
                route.fulfill(response=response)
            page.wait_for_load_state("networkidle")
            page.unroute("**/api/**", delay_a)
            counts("late_a_lists_cannot_overwrite_newer_b", latest_b)
            check("late_a_task_cannot_overwrite_newer_b", task_b in page.locator(".hero-copy").inner_text())
            page.get_by_role("button", name="攻击图", exact=True).click()
            page.wait_for_function("document.querySelector('.attack-graph-canvas')?._cyreg?.cy?.nodes().length > 0")
            rendered_ids = page.locator(".attack-graph-canvas").evaluate("el => el._cyreg.cy.nodes().map(node => node.data('contractId'))")
            check("late_a_graph_cannot_overwrite_newer_b", set(rendered_ids) == {node["id"] for node in latest_b["graph"]["nodes"]})
            page.get_by_role("button", name="溯源结果", exact=True).click()
            check("late_a_trace_cannot_overwrite_newer_b", latest_b["trace"]["trace_id"] in page.locator(".trace-hero").inner_text())

            # Also race two revisions of the same task, where task ID is unchanged.
            held.clear()
            held_paths.clear()
            page.route("**/api/**", delay_a)
            query(task_a, "same_id_old_revision", wait=False)
            for _ in range(100):
                if len(held) == 5:
                    break
                page.wait_for_timeout(20)
            check("same_id_race_holds_five_old_responses", len(held) == 5)
            ingest(task_a, start=15, count=3)
            latest_a = snapshot(task_a)
            query(task_a, "same_id_newer_revision")
            counts("same_id_newer_revision_reads_eighteen_events", latest_a)
            for route, response in held:
                route.fulfill(response=response)
            page.wait_for_load_state("networkidle")
            page.unroute("**/api/**", delay_a)
            counts("same_id_late_old_revision_does_not_revert_counts", latest_a)
            page.get_by_role("button", name="攻击图", exact=True).click()
            page.wait_for_function("document.querySelector('.attack-graph-canvas')?._cyreg?.cy?.nodes().length > 0")
            first_edge = latest_a["graph"]["edges"][0]
            page.get_by_label("选择图关系", exact=True).select_option(first_edge["id"])
            evidence_ids = page.locator(".attack-graph-evidence li code").all_text_contents()
            check("same_id_late_old_graph_cannot_revert_evidence", set(evidence_ids) == set(first_edge["evidence_event_ids"] + first_edge["evidence_alert_ids"]))

            for resource, label, preview, navigation in (
                ("events", "标准化事件", ".event-preview", "事件流"),
                ("alerts", "检测告警", ".alert-preview", "检测告警"),
            ):
                message = f"synthetic {resource} failure"

                def fail(route):
                    route.fulfill(status=503, content_type="application/json", body=json.dumps({"detail": message}))

                pattern = f"**/api/{resource}"
                page.route(pattern, fail)
                query(task_a, resource + "_failed_query")
                check(resource + "_failure_metric_is_unknown_not_zero", metric(label) == "-")
                check(resource + "_failure_is_visible_on_overview", message in page.locator(preview).inner_text())
                check(resource + "_failure_navigation_hides_count", page.get_by_role("button", name=navigation, exact=True).locator("small").count() == 0)
                page.screenshot(path=str(args.output_dir / f"{resource}-failure.png"), full_page=True)
                page.get_by_role("button", name=navigation, exact=True).click()
                check(resource + "_failure_panel_not_successful_empty", "读取失败" in page.locator(".table-panel").inner_text() and
                      message in page.locator(".table-panel").inner_text() and page.locator(".empty-state").count() == 0)
                page.unroute(pattern, fail)
                query(task_a, resource + "_recovery_query")
                counts(resource + "_same_task_retry_recovers", latest_a)

            query("task_refresh_browser_missing_" + run_id, "missing_task")
            check("missing_task_shows_error", "task not found" in page.locator(".hero-panel").inner_text() and
                  metric("攻击图节点") == "-")
            query(task_a, "return_after_missing_task")
            counts("return_after_missing_task_recovers", latest_a)
            ingest(task_a, start=18, count=2)
            with page.expect_response(lambda response: urlparse(response.url).path == f"/api/tasks/{task_a}"):
                page.get_by_role("button", name="刷新全部数据", exact=True).click()
            page.wait_for_load_state("networkidle")
            counts("manual_refresh_still_works", snapshot(task_a))
        except Exception as error:
            check("script_completed", False, str(error))
            page.screenshot(path=str(args.output_dir / "failure.png"), full_page=True)
            (args.output_dir / "failure.html").write_text(page.content(), encoding="utf-8")
        finally:
            check("no_browser_javascript_exceptions", not report["page_errors"], report["page_errors"])
            report["note"] = "Expected browser HTTP errors include deliberately injected 503 and missing-task 404 responses."
            (args.output_dir / "browser-task-refresh-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            browser.close()
    return 0 if all(check["passed"] for check in report["checks"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
