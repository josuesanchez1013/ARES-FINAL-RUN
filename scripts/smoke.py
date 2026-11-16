#!/usr/bin/env python3
"""End-to-end smoke test against a running ARES service (mock mode).

Starts a run over HTTP, waits for it to finish, records a review decision and
downloads every export. Usage: python scripts/smoke.py http://127.0.0.1:8099
"""
import json
import sys
import time

import httpx

base = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8080"
client = httpx.Client(base_url=base, timeout=30)


def step(label, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}  {label} {detail}")
    if not ok:
        sys.exit(1)


health = client.get("/api/health").json()
step("service health", health["status"] == "ok" and health["pipeline_ready"], f"(mode: {health['mode']})")
step("frontend is served", "<div id=\"root\">" in client.get("/").text)
settings = client.get("/api/settings").json()

refused = client.post("/api/runs", data={"classification": "Classified", "sensitivity": "None",
                                         "primary_model": settings["models"][0]},
                      files={"tool1": ("a.ckl", b"<CHECKLIST/>"), "tool2": ("b.csv", b"a,b")})
step("classified upload refused", refused.status_code == 422)

started = client.post("/api/runs", data={"classification": "CUI", "sensitivity": "None",
                                         "primary_model": settings["models"][0]},
                      files={"tool1": ("a.ckl", b"<CHECKLIST><HOST_NAME>h</HOST_NAME></CHECKLIST>"),
                             "tool2": ("b.csv", b"a,b")})
step("run started", started.status_code == 201)
run_id = started.json()["id"]
second = client.post("/api/runs", data={"classification": "CUI", "sensitivity": "None",
                                        "primary_model": settings["models"][0]},
                     files={"tool1": ("a.ckl", b"<CHECKLIST/>"), "tool2": ("b.csv", b"a,b")})
step("second start refused while active", second.status_code in (409, 201), f"(HTTP {second.status_code})")

deadline = time.time() + 120
while time.time() < deadline:
    run = client.get(f"/api/runs/{run_id}").json()
    if run["status"] in ("completed", "failed"):
        break
    time.sleep(0.2)
step("run completed", run["status"] == "completed", f"({run.get('error') or 'ok'})")

summary = client.get(f"/api/runs/{run_id}/summary").json()
step("summary", summary["total"] > 0, f"({summary['total']} rules, {summary['review_pending']} to review)")
rows = client.get(f"/api/runs/{run_id}/findings?page_size=5").json()
step("findings page", len(rows["rows"]) > 0)
events = client.get(f"/api/runs/{run_id}/events?follow=false").text.count("\ndata: ") + 1
step("event history replays", events > 10, f"({events} events)")

review = client.get(f"/api/runs/{run_id}/review").json()
if review["required"]:
    vuln = review["required"][0]["vuln_id"]
    done = client.post(f"/api/runs/{run_id}/decisions/{vuln}", json={"action": "approve"})
    step("review decision saved", done.status_code == 200, f"({vuln})")
for fmt in ("ckl", "cklb", "csv", "json"):
    export = client.get(f"/api/runs/{run_id}/export/{fmt}")
    ok = export.status_code == 200 and len(export.content) > 50
    if fmt in ("cklb", "json"):
        json.loads(export.content)
    step(f"export {fmt}", ok, f"({len(export.content)} bytes)")
print("\nSmoke test passed.")
