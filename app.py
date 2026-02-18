"""
app.py - Flask web server for the Privacy Compliance Scanner.

Wraps the existing scanner.py and database.py into a web interface
with real-time progress updates via Server-Sent Events (SSE).

Run:  python app.py
Open: http://localhost:5000
"""

import json
import os
import threading
import uuid
from datetime import datetime
from queue import Queue, Empty

from flask import (
    Flask, render_template, request, jsonify, Response, send_from_directory
)
from playwright.sync_api import sync_playwright

import database
import scanner

app = Flask(__name__)

# ────────────────────────────────────────────────────────────────────
# In-memory store for active / recent scans.
# Key: scan_id  Value: { queue, thread, result, error, done }
# ────────────────────────────────────────────────────────────────────
active_scans = {}
active_batch_scans = {}


# ────────────────────────────────────────────────────────────────────
# ROUTES
# ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the single-page frontend."""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """
    Start a new privacy scan.

    Expects JSON: {"url": "example.com"}
    Returns JSON: {"scan_id": "..."}
    """
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400

    # Normalise the URL (add https:// if missing).
    url = scanner.normalize_url(url)

    scan_id = str(uuid.uuid4())
    q = Queue()

    active_scans[scan_id] = {
        "queue": q,
        "result": None,
        "error": None,
        "done": False,
    }

    def run_scan():
        """Background thread: launches Playwright and runs the scan."""
        try:
            database.init_db()

            def status_callback(message, step, total_steps):
                q.put({
                    "event": "status",
                    "data": {
                        "message": message,
                        "step": step,
                        "total_steps": total_steps,
                    },
                })

            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                result = scanner.scan_url(browser, url, status_callback=status_callback)
                browser.close()

            active_scans[scan_id]["result"] = result
            q.put({"event": "complete", "data": result})

        except Exception as e:
            active_scans[scan_id]["error"] = str(e)
            q.put({"event": "scan_error", "data": {"message": str(e)}})

        finally:
            active_scans[scan_id]["done"] = True
            q.put(None)  # sentinel — ends the SSE stream

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    active_scans[scan_id]["thread"] = thread

    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/<scan_id>/stream")
def scan_stream(scan_id):
    """
    SSE endpoint — streams real-time progress events for a scan.

    Event types:
      status     — progress update (step N of 20)
      complete   — final results payload
      scan_error — scan failed
      done       — terminal event, close the stream
    """
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404

    def generate():
        q = active_scans[scan_id]["queue"]
        while True:
            try:
                msg = q.get(timeout=120)
                if msg is None:
                    yield f"event: done\ndata: {json.dumps({'status': 'finished'})}\n\n"
                    break
                event_type = msg.get("event", "status")
                data = msg.get("data", {})
                yield f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
            except Empty:
                # Keepalive to prevent proxy/browser timeout.
                yield ": keepalive\n\n"

        # Clean up after a delay (keep results for 10 minutes).
        def cleanup():
            import time
            time.sleep(600)
            active_scans.pop(scan_id, None)

        threading.Thread(target=cleanup, daemon=True).start()

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.route("/api/scan/<scan_id>/result")
def scan_result(scan_id):
    """Get the final result of a completed scan as JSON."""
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404

    scan = active_scans[scan_id]
    if not scan["done"]:
        return jsonify({"status": "in_progress"}), 202

    if scan["error"]:
        return jsonify({"error": scan["error"]}), 500

    return jsonify(scan["result"])


@app.route("/screenshots/<path:filename>")
def serve_screenshot(filename):
    """Serve screenshot images from the screenshots directory."""
    return send_from_directory("screenshots", filename)


@app.route("/api/scan/<scan_id>/pdf")
def download_pdf(scan_id):
    """Generate and return a PDF privacy compliance report."""
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404

    scan = active_scans[scan_id]
    if not scan["done"] or not scan["result"]:
        return jsonify({"error": "Scan not yet complete"}), 404

    result = scan["result"]

    from fpdf import FPDF

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ── Title ──────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 22)
    pdf.cell(0, 15, "Privacy Compliance Report", ln=True, align="C")
    pdf.ln(3)

    # ── URL and date ───────────────────────────────────────────
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 8, f"URL: {result['url']}", ln=True)
    pdf.cell(0, 8, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(5)

    # ── Verdict banner ─────────────────────────────────────────
    if result["still_tracking"] == "yes":
        pdf.set_fill_color(255, 71, 87)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 12, "  VIOLATION: Still tracking after opt-out", ln=True, fill=True)
    elif result["still_tracking"] == "inconclusive":
        pdf.set_fill_color(255, 165, 2)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 12, "  INCONCLUSIVE: Opt-out could not be verified", ln=True, fill=True)
    else:
        pdf.set_fill_color(46, 213, 115)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 12, "  CLEAN: Tracking stopped after opt-out", ln=True, fill=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(8)

    # ── California Business Registration ───────────────────────
    ca_reg = result.get("ca_registration")
    if ca_reg and ca_reg.get("status") == "found":
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "California Business Registration", ln=True)
        pdf.set_font("Helvetica", "", 11)
        if ca_reg.get("entity_name"):
            pdf.cell(0, 7, f"Entity Name: {ca_reg['entity_name']}", ln=True)
        if ca_reg.get("entity_number"):
            pdf.cell(0, 7, f"Entity Number: {ca_reg['entity_number']}", ln=True)
        if ca_reg.get("entity_status"):
            pdf.cell(0, 7, f"Status: {ca_reg['entity_status']}", ln=True)
        if ca_reg.get("entity_type"):
            pdf.cell(0, 7, f"Type: {ca_reg['entity_type']}", ln=True)
        if ca_reg.get("formation_date"):
            pdf.cell(0, 7, f"Formation Date: {ca_reg['formation_date']}", ln=True)
        if ca_reg.get("registered_agent"):
            pdf.cell(0, 7, f"Registered Agent: {ca_reg['registered_agent']}", ln=True)
        if ca_reg.get("agent_address"):
            pdf.cell(0, 7, f"Agent Address: {ca_reg['agent_address']}", ln=True)
        pdf.ln(5)

    # ── Scan details ───────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Scan Details", ln=True)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, f"Opt-out banner found: {result['opt_out_found']}", ln=True)
    pdf.cell(0, 7, f"Opt-out clicked: {result['opt_out_clicked']}", ln=True)
    pdf.cell(0, 7, f"Trackers before opt-out: {len(result['trackers_before'])}", ln=True)
    pdf.cell(0, 7, f"Trackers after opt-out: {len(result['trackers_after'])}", ln=True)
    pdf.ln(5)

    # ── Trackers before (list) ─────────────────────────────────
    if result["trackers_before"]:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 9, "Trackers Before Opt-Out:", ln=True)
        pdf.set_font("Helvetica", "", 10)
        for t in result["trackers_before"]:
            pdf.cell(0, 6, f"  - {t}", ln=True)
        pdf.ln(3)

    # ── Flagged domains table ──────────────────────────────────
    flagged = result.get("flagged_domains", {})
    if flagged:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Flagged Tracker Domains (Post-Opt-Out)", ln=True)
        pdf.ln(2)

        # Table header
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(34, 38, 57)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(85, 8, "  Domain", border=1, fill=True)
        pdf.cell(25, 8, "Requests", border=1, fill=True, align="C")
        pdf.cell(70, 8, "  Matched Rule", border=1, fill=True)
        pdf.ln()
        pdf.set_text_color(0, 0, 0)

        # Table rows
        pdf.set_font("Helvetica", "", 9)
        for domain, info in sorted(flagged.items()):
            pdf.cell(85, 7, f"  {domain[:42]}", border=1)
            pdf.cell(25, 7, str(info["count"]), border=1, align="C")
            pdf.cell(70, 7, f"  {info['matched_rule'][:34]}", border=1)
            pdf.ln()
        pdf.ln(5)

    # ── Notes ──────────────────────────────────────────────────
    notes = result.get("notes", [])
    if notes:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 9, "Notes:", ln=True)
        pdf.set_font("Helvetica", "", 10)
        for note in notes:
            # Truncate very long notes for PDF readability.
            short = note[:200] + "..." if len(note) > 200 else note
            pdf.multi_cell(0, 6, f"  - {short}")
        pdf.ln(3)

    # ── Screenshots ────────────────────────────────────────────
    for label, key in [("Before Opt-Out", "screenshot_before"),
                       ("After Opt-Out", "screenshot_after")]:
        path = result.get(key)
        if path and os.path.exists(path):
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 10, f"Screenshot: {label}", ln=True)
            pdf.ln(3)
            try:
                pdf.image(path, x=10, w=190)
            except Exception:
                pdf.set_font("Helvetica", "", 11)
                pdf.cell(0, 10, "(Screenshot could not be embedded)", ln=True)

    # ── Output ─────────────────────────────────────────────────
    pdf_bytes = pdf.output()
    domain = scanner.get_domain(result["url"]).replace(":", "_")

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="privacy-report-{domain}.pdf"'
        },
    )


@app.route("/api/scan/<scan_id>/evidence")
def download_evidence(scan_id):
    """Generate and return a legal evidence package as a ZIP file."""
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404

    scan = active_scans[scan_id]
    if not scan["done"] or not scan["result"]:
        return jsonify({"error": "Scan not yet complete"}), 404

    result = scan["result"]
    if result.get("still_tracking") not in ("yes", "inconclusive"):
        return jsonify({"error": "No violations found — evidence package only available for violations or inconclusive results"}), 400

    from evidence import generate_evidence_package
    zip_bytes = generate_evidence_package(result)

    domain = scanner.get_domain(result["url"]).replace(":", "_")
    date_str = datetime.now().strftime("%Y-%m-%d")
    filename = f"{domain}_privacy_violation_evidence_{date_str}.zip"

    return Response(
        zip_bytes,
        mimetype="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ────────────────────────────────────────────────────────────────────
# BATCH SCANNING
# ────────────────────────────────────────────────────────────────────

@app.route("/api/batch-scan", methods=["POST"])
def start_batch_scan():
    """
    Start a batch privacy scan for multiple domains.

    Expects JSON: {"urls": ["kos.com", "drinkag1.com", ...]}
    Returns JSON: {"batch_id": "..."}
    """
    data = request.get_json(silent=True) or {}
    urls = data.get("urls", [])

    # Filter empty strings and normalize
    urls = [scanner.normalize_url(u.strip()) for u in urls if u.strip()]
    if not urls:
        return jsonify({"error": "At least one URL is required"}), 400

    batch_id = str(uuid.uuid4())
    q = Queue()

    active_batch_scans[batch_id] = {
        "queue": q,
        "urls": urls,
        "results": {},
        "scan_ids": {},
        "current_index": 0,
        "stop_requested": False,
        "done": False,
    }

    def run_batch():
        violations = 0
        clean = 0
        try:
            database.init_db()
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                for i, url in enumerate(urls):
                    if active_batch_scans[batch_id]["stop_requested"]:
                        break

                    active_batch_scans[batch_id]["current_index"] = i

                    # Notify: starting this domain
                    q.put({
                        "event": "batch_status",
                        "data": {
                            "current_url": url,
                            "current_index": i,
                            "total": len(urls),
                            "message": f"Starting scan of {url}",
                            "step": 0,
                            "total_steps": 20,
                        },
                    })

                    # Create a scan_id so evidence/PDF routes work
                    scan_id = str(uuid.uuid4())

                    def status_callback(message, step, total_steps, _url=url, _i=i):
                        q.put({
                            "event": "batch_status",
                            "data": {
                                "current_url": _url,
                                "current_index": _i,
                                "total": len(urls),
                                "message": message,
                                "step": step,
                                "total_steps": total_steps,
                            },
                        })

                    try:
                        result = scanner.scan_url(browser, url, status_callback=status_callback)

                        # Store in active_scans so existing evidence/PDF routes work
                        active_scans[scan_id] = {
                            "queue": Queue(),
                            "result": result,
                            "error": None,
                            "done": True,
                        }

                        active_batch_scans[batch_id]["results"][url] = result
                        active_batch_scans[batch_id]["scan_ids"][url] = scan_id

                        if result.get("still_tracking") == "yes":
                            violations += 1
                        else:
                            clean += 1

                        q.put({
                            "event": "domain_complete",
                            "data": {
                                "url": url,
                                "scan_id": scan_id,
                                "result": result,
                            },
                        })

                    except Exception as e:
                        q.put({
                            "event": "domain_complete",
                            "data": {
                                "url": url,
                                "scan_id": None,
                                "result": {
                                    "url": url,
                                    "still_tracking": "error",
                                    "error": str(e),
                                },
                            },
                        })

                browser.close()

        except Exception as e:
            q.put({"event": "batch_error", "data": {"message": str(e)}})

        finally:
            stopped = active_batch_scans[batch_id]["stop_requested"]
            q.put({
                "event": "batch_complete",
                "data": {
                    "total": len(urls),
                    "violations": violations,
                    "clean": clean,
                    "stopped": stopped,
                },
            })
            active_batch_scans[batch_id]["done"] = True
            q.put(None)

    thread = threading.Thread(target=run_batch, daemon=True)
    thread.start()
    active_batch_scans[batch_id]["thread"] = thread

    return jsonify({"batch_id": batch_id})


@app.route("/api/batch-scan/<batch_id>/stream")
def batch_scan_stream(batch_id):
    """SSE endpoint for batch scan progress."""
    if batch_id not in active_batch_scans:
        return jsonify({"error": "Batch scan not found"}), 404

    def generate():
        q = active_batch_scans[batch_id]["queue"]
        while True:
            try:
                msg = q.get(timeout=120)
                if msg is None:
                    yield f"event: done\ndata: {json.dumps({'status': 'finished'})}\n\n"
                    break
                event_type = msg.get("event", "batch_status")
                data = msg.get("data", {})
                yield f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
            except Empty:
                yield ": keepalive\n\n"

        def cleanup():
            import time
            time.sleep(600)
            active_batch_scans.pop(batch_id, None)

        threading.Thread(target=cleanup, daemon=True).start()

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.route("/api/batch-scan/<batch_id>/stop", methods=["POST"])
def stop_batch_scan(batch_id):
    """Request a batch scan to stop after the current domain finishes."""
    if batch_id not in active_batch_scans:
        return jsonify({"error": "Batch scan not found"}), 404

    active_batch_scans[batch_id]["stop_requested"] = True
    return jsonify({"status": "stopping"})


# ────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    database.init_db()
    print("\n  Privacy Scanner Web UI")
    print("  http://localhost:8080\n")
    app.run(host="0.0.0.0", debug=False, port=8080, threaded=True)
