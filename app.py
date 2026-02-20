"""
app.py - Flask web server for the Privacy Compliance Scanner.

Wraps the existing scanner.py and database.py into a web interface
with real-time progress updates via Server-Sent Events (SSE).

Run:  python app.py
Open: http://localhost:5000
"""

import json
import multiprocessing
import os
import threading
import time
import traceback
import uuid
from datetime import datetime
from queue import Queue, Empty

from flask import (
    Flask, render_template, request, jsonify, Response, send_from_directory
)
from playwright.sync_api import sync_playwright

import database
import scanner

MAX_SCAN_TIME = 90  # Hard kill after 90 seconds — same as CLI


def _scan_worker(url, mp_result_queue, mp_status_queue):
    """
    Runs in a SEPARATE PROCESS. Launches its own browser, runs the scan,
    sends status updates and the final result via multiprocessing queues.
    If this process hangs, the parent kills it with SIGKILL.
    """
    try:
        database.init_db()

        def status_callback(message, step, total_steps, elapsed=0):
            try:
                mp_status_queue.put({
                    "message": message,
                    "step": step,
                    "total_steps": total_steps,
                    "elapsed": round(elapsed, 1),
                }, block=False)
            except Exception:
                pass  # Don't let queue errors kill the scan

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            result = scanner.scan_url(browser, url, status_callback=status_callback)
            browser.close()
        mp_result_queue.put(result)
    except Exception as e:
        mp_result_queue.put({
            "url": url,
            "error": str(e),
            "still_tracking": "unknown",
            "tiktok_trackers_after": [],
        })

app = Flask(__name__)

# Directory for pre-generated evidence packages.
EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), "evidence")
os.makedirs(EVIDENCE_DIR, exist_ok=True)


def _sanitize_for_pdf(text):
    """Replace Unicode characters that Helvetica can't render."""
    replacements = {
        "\u2014": "--", "\u2013": "-", "\u2018": "'", "\u2019": "'",
        "\u201c": '"', "\u201d": '"', "\u2026": "...", "\u00a0": " ",
        "\u2192": "->", "\u2190": "<-", "\u2194": "<->",
        "\u2022": "*", "\u25cf": "*", "\u2713": "[x]", "\u2717": "[ ]",
        "\u00b7": ".",
    }
    for char, repl in replacements.items():
        text = text.replace(char, repl)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _save_result_to_disk(scan_id, result):
    """Persist the scan result dict as JSON so downloads survive server restarts."""
    try:
        result_path = os.path.join(EVIDENCE_DIR, f"{scan_id}_result.json")
        with open(result_path, "w") as f:
            json.dump(result, f)
    except Exception as e:
        print(f"[!] Failed to save result JSON for {scan_id}: {e}")


def _load_result_from_disk(scan_id):
    """Load a previously saved scan result from disk. Returns dict or None."""
    result_path = os.path.join(EVIDENCE_DIR, f"{scan_id}_result.json")
    if not os.path.exists(result_path):
        return None
    try:
        with open(result_path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Failed to load result JSON for {scan_id}: {e}")
        return None


def _pregenerate_evidence(scan_id, result):
    """Pre-generate the evidence ZIP in a background thread so it's ready for download."""
    # Always save the result JSON to disk (needed for PDF/evidence regeneration).
    _save_result_to_disk(scan_id, result)

    if result.get("still_tracking") not in ("yes", "inconclusive"):
        return  # No violations — no evidence to generate.

    def _generate():
        try:
            from evidence import generate_evidence_package
            zip_bytes = generate_evidence_package(result)
            out_path = os.path.join(EVIDENCE_DIR, f"{scan_id}.zip")
            with open(out_path, "wb") as f:
                f.write(zip_bytes)
            print(f"[*] Evidence pre-generated: {out_path} ({len(zip_bytes)} bytes)")
        except Exception as e:
            print(f"[!] Evidence pre-generation failed for {scan_id}: {e}")
            traceback.print_exc()

    threading.Thread(target=_generate, daemon=True).start()

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
        """Background thread: runs scan in a SEPARATE PROCESS with hard kill timeout."""
        try:
            mp_result_queue = multiprocessing.Queue()
            mp_status_queue = multiprocessing.Queue()

            proc = multiprocessing.Process(
                target=_scan_worker,
                args=(url, mp_result_queue, mp_status_queue),
            )
            proc.start()
            start_time = time.time()

            # Relay status updates from the subprocess to the SSE queue
            while proc.is_alive():
                # Check timeout
                elapsed = time.time() - start_time
                if elapsed > MAX_SCAN_TIME:
                    proc.kill()
                    proc.join()
                    q.put({"event": "scan_error", "data": {
                        "message": f"Scan timed out after {MAX_SCAN_TIME}s — killed"
                    }})
                    active_scans[scan_id]["error"] = f"Timeout after {MAX_SCAN_TIME}s"
                    return

                # Drain status messages
                while not mp_status_queue.empty():
                    try:
                        status = mp_status_queue.get_nowait()
                        q.put({"event": "status", "data": status})
                    except Exception:
                        break

                time.sleep(0.2)

            proc.join()

            # Drain any remaining status messages
            while not mp_status_queue.empty():
                try:
                    status = mp_status_queue.get_nowait()
                    q.put({"event": "status", "data": status})
                except Exception:
                    break

            # Get the result
            try:
                result = mp_result_queue.get(timeout=5)
            except Exception:
                result = {
                    "url": url,
                    "still_tracking": "unknown",
                    "tiktok_trackers_after": [],
                    "error": "Scan process ended without returning results",
                }

            active_scans[scan_id]["result"] = result
            q.put({"event": "complete", "data": result})

            # Pre-generate evidence package in background.
            _pregenerate_evidence(scan_id, result)

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
      status     — progress update (step N of 19)
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
    if scan_id in active_scans:
        scan = active_scans[scan_id]
        if not scan["done"]:
            return jsonify({"status": "in_progress"}), 202
        if scan["error"]:
            return jsonify({"error": scan["error"]}), 500
        return jsonify(scan["result"])

    # Not in memory — check disk.
    result = _load_result_from_disk(scan_id)
    if result is not None:
        return jsonify(result)

    return jsonify({"error": "Scan not found"}), 404


@app.route("/screenshots/<path:filename>")
def serve_screenshot(filename):
    """Serve screenshot images from the screenshots directory."""
    return send_from_directory("screenshots", filename)


@app.route("/api/scan/<scan_id>/pdf")
def download_pdf(scan_id):
    """Generate and return a PDF privacy compliance report."""
    # Try in-memory first, then fall back to disk.
    result = None
    if scan_id in active_scans:
        scan = active_scans[scan_id]
        if not scan["done"] or not scan["result"]:
            return jsonify({"error": "Scan not yet complete", "retry": True}), 202
        result = scan["result"]
    else:
        result = _load_result_from_disk(scan_id)

    if result is None:
        return jsonify({"error": "Scan not found", "retry": False}), 404

    try:
        pdf_bytes = _generate_pdf_report(result)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"PDF generation failed: {e}", "retry": False}), 500

    domain = scanner.get_domain(result["url"]).replace(":", "_")

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="privacy-report-{domain}.pdf"'
        },
    )


def _generate_pdf_report(result):
    """Build the PDF bytes for a scan result. Raises on failure."""
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
        pdf.cell(0, 12, "  VIOLATION: TikTok tracking continues after opt-out", ln=True, fill=True)
    elif result["still_tracking"] == "inconclusive":
        pdf.set_fill_color(255, 165, 2)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 12, "  INCONCLUSIVE: Opt-out could not be verified", ln=True, fill=True)
    else:
        pdf.set_fill_color(46, 213, 115)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 12, "  CLEAN: No TikTok tracking after opt-out", ln=True, fill=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(8)

    # ── Scan details ───────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Scan Details", ln=True)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, f"Opt-out banner found: {result['opt_out_found']}", ln=True)
    pdf.cell(0, 7, f"Opt-out clicked: {result['opt_out_clicked']}", ln=True)
    pdf.cell(0, 7, f"Trackers before opt-out: {len(result['trackers_before'])}", ln=True)
    tiktok_after = result.get("tiktok_trackers_after", [])
    all_after = result.get("trackers_after", [])
    other_after = [t for t in all_after if t not in tiktok_after]
    pdf.cell(0, 7, f"TikTok trackers after opt-out: {len(tiktok_after)}", ln=True)
    pdf.cell(0, 7, f"Other trackers after opt-out: {len(other_after)}", ln=True)
    pdf.ln(5)

    # ── Trackers before (list) ─────────────────────────────────
    if result["trackers_before"]:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 9, "Trackers Before Opt-Out:", ln=True)
        pdf.set_font("Helvetica", "", 10)
        for t in result["trackers_before"]:
            pdf.cell(0, 6, _sanitize_for_pdf(f"  - {t}"), ln=True)
        pdf.ln(3)

    # ── Flagged domains table ──────────────────────────────────
    flagged = result.get("flagged_domains", {})
    if flagged:
        # Split into TikTok and other trackers
        tiktok_flagged = {d: i for d, i in flagged.items()
                         if "tiktok" in d.lower() or "tiktok" in i.get("matched_rule", "").lower()}
        other_flagged = {d: i for d, i in flagged.items() if d not in tiktok_flagged}

        # TikTok section (primary — red highlight)
        if tiktok_flagged:
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 10, "TikTok Trackers (Post-Opt-Out) - VIOLATION", ln=True)
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_fill_color(255, 71, 87)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(85, 8, "  Domain", border=1, fill=True)
            pdf.cell(25, 8, "Requests", border=1, fill=True, align="C")
            pdf.cell(70, 8, "  Matched Rule", border=1, fill=True)
            pdf.ln()
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "", 9)
            for fdomain, info in sorted(tiktok_flagged.items()):
                pdf.set_fill_color(255, 240, 240)
                pdf.cell(85, 7, f"  {fdomain[:42]}", border=1, fill=True)
                pdf.cell(25, 7, str(info["count"]), border=1, align="C", fill=True)
                pdf.cell(70, 7, f"  {info['matched_rule'][:34]}", border=1, fill=True)
                pdf.ln()
            pdf.ln(5)

        # Other trackers (informational — gray)
        if other_flagged:
            pdf.set_font("Helvetica", "B", 12)
            pdf.set_text_color(120, 120, 120)
            pdf.cell(0, 10, "Other Trackers Detected (Informational)", ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_fill_color(100, 100, 110)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(85, 8, "  Domain", border=1, fill=True)
            pdf.cell(25, 8, "Requests", border=1, fill=True, align="C")
            pdf.cell(70, 8, "  Matched Rule", border=1, fill=True)
            pdf.ln()
            pdf.set_text_color(120, 120, 120)
            pdf.set_font("Helvetica", "", 9)
            for fdomain, info in sorted(other_flagged.items()):
                pdf.cell(85, 7, f"  {fdomain[:42]}", border=1)
                pdf.cell(25, 7, str(info["count"]), border=1, align="C")
                pdf.cell(70, 7, f"  {info['matched_rule'][:34]}", border=1)
                pdf.ln()
            pdf.set_text_color(0, 0, 0)
            pdf.ln(5)

    # ── Notes ──────────────────────────────────────────────────
    notes = result.get("notes", [])
    if notes:
        # Reset cursor to left margin before multi_cell.
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 9, "Notes:", ln=True)
        pdf.set_font("Helvetica", "", 10)
        for note in notes:
            short = note[:200] + "..." if len(note) > 200 else note
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, 6, _sanitize_for_pdf(f"  - {short}"))
        pdf.ln(3)

    # ── Screenshots ────────────────────────────────────────────
    for label, key in [("Before Opt-Out", "screenshot_before"),
                       ("After Opt-Out", "screenshot_after"),
                       ("Product Page", "screenshot_product")]:
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

    # ── TikTok Network Evidence (composite) ────────────────────
    domain_safe = scanner.get_domain(result["url"]).replace(":", "_")
    evidence_img = os.path.join("screenshots", f"evidence_tiktok_network_{domain_safe}.png")
    if not os.path.exists(evidence_img):
        # Try generating it on the fly.
        try:
            from evidence import generate_tiktok_evidence_images
            generate_tiktok_evidence_images(result, "screenshots")
        except Exception:
            pass
    if os.path.exists(evidence_img):
        pdf.add_page("L")  # Landscape for wide image
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "TikTok Network Evidence (DevTools Capture)", ln=True)
        pdf.ln(3)
        try:
            pdf.image(evidence_img, x=5, w=287)  # Full landscape width
        except Exception:
            pdf.set_font("Helvetica", "", 11)
            pdf.cell(0, 10, "(Evidence image could not be embedded)", ln=True)

    return bytes(pdf.output())


@app.route("/api/scan/<scan_id>/evidence")
def download_evidence(scan_id):
    """Generate and return a legal evidence package as a ZIP file."""
    # Try in-memory first, then fall back to disk.
    result = None
    if scan_id in active_scans:
        scan = active_scans[scan_id]
        if not scan["done"] or not scan["result"]:
            return jsonify({"error": "Scan not yet complete", "retry": True}), 202
        result = scan["result"]
    else:
        # Not in memory — check disk for saved result.
        result = _load_result_from_disk(scan_id)

    if result is None:
        return jsonify({"error": "Scan not found", "retry": False}), 404

    if result.get("still_tracking") not in ("yes", "inconclusive"):
        return jsonify({
            "error": "No violations found -- evidence package only available for violations",
            "retry": False,
        }), 400

    domain = scanner.get_domain(result["url"]).replace(":", "_")
    date_str = datetime.now().strftime("%Y-%m-%d")
    filename = f"{domain}_privacy_violation_evidence_{date_str}.zip"

    # Check for pre-generated evidence file first.
    prebuilt_path = os.path.join(EVIDENCE_DIR, f"{scan_id}.zip")
    if os.path.exists(prebuilt_path) and os.path.getsize(prebuilt_path) > 0:
        with open(prebuilt_path, "rb") as f:
            zip_bytes = f.read()
    else:
        # Fallback: generate on the fly.
        try:
            from evidence import generate_evidence_package
            zip_bytes = generate_evidence_package(result)

            # Save for future requests.
            try:
                with open(prebuilt_path, "wb") as f:
                    f.write(zip_bytes)
            except Exception:
                pass
        except Exception as e:
            traceback.print_exc()
            return jsonify({"error": f"Evidence generation failed: {e}", "retry": False}), 500

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

                # ── Run scan in separate process with hard kill timeout ──
                mp_result_queue = multiprocessing.Queue()
                mp_status_queue = multiprocessing.Queue()

                proc = multiprocessing.Process(
                    target=_scan_worker,
                    args=(url, mp_result_queue, mp_status_queue),
                )
                proc.start()
                start_time = time.time()
                timed_out = False

                # Relay status updates while process is alive
                while proc.is_alive():
                    elapsed = time.time() - start_time
                    if elapsed > MAX_SCAN_TIME:
                        proc.kill()
                        proc.join()
                        timed_out = True
                        break

                    # Drain status messages
                    while not mp_status_queue.empty():
                        try:
                            status = mp_status_queue.get_nowait()
                            status["current_url"] = url
                            status["current_index"] = i
                            status["total"] = len(urls)
                            q.put({"event": "batch_status", "data": status})
                        except Exception:
                            break

                    time.sleep(0.2)

                if not timed_out:
                    proc.join()

                # Drain remaining status messages
                while not mp_status_queue.empty():
                    try:
                        mp_status_queue.get_nowait()
                    except Exception:
                        break

                if timed_out:
                    result = {
                        "url": url,
                        "still_tracking": "timeout",
                        "tiktok_trackers_after": [],
                        "trackers_after": [],
                        "trackers_before": [],
                        "opt_out_found": "unknown",
                        "opt_out_clicked": "unknown",
                        "error": f"Scan timed out after {MAX_SCAN_TIME}s — killed",
                    }
                else:
                    try:
                        result = mp_result_queue.get(timeout=5)
                    except Exception:
                        result = {
                            "url": url,
                            "still_tracking": "unknown",
                            "tiktok_trackers_after": [],
                            "error": "Scan process ended without returning results",
                        }

                # Store in active_scans so existing evidence/PDF routes work
                active_scans[scan_id] = {
                    "queue": Queue(),
                    "result": result,
                    "error": None,
                    "done": True,
                }

                active_batch_scans[batch_id]["results"][url] = result
                active_batch_scans[batch_id]["scan_ids"][url] = scan_id

                # Pre-generate evidence package in background (skip for timeouts).
                if not timed_out:
                    _pregenerate_evidence(scan_id, result)

                st = result.get("still_tracking")
                if st == "yes":
                    violations += 1
                elif st in ("timeout", "inconclusive"):
                    pass  # Don't count as clean or violation
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
