"""
database.py - Handles saving and retrieving privacy scan results.

This module creates a SQLite database to store the results of privacy
compliance scans. Each row represents one scan of one website.
"""

import sqlite3
from datetime import datetime

# The database file will be created in the same folder as this script.
DATABASE_NAME = "scan_results.db"


def init_db():
    """
    Create the database and the 'scans' table if they don't already exist.

    Call this once when the program starts. It's safe to call multiple
    times — it won't erase existing data because of IF NOT EXISTS.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id                      INTEGER PRIMARY KEY AUTOINCREMENT,
            url                     TEXT    NOT NULL,
            scan_date               TEXT    NOT NULL,
            opt_out_found           TEXT    NOT NULL DEFAULT 'no',
            opt_out_clicked         TEXT    NOT NULL DEFAULT 'no',
            trackers_before_optout  TEXT    NOT NULL DEFAULT '[]',
            trackers_after_optout   TEXT    NOT NULL DEFAULT '[]',
            still_tracking          TEXT    NOT NULL DEFAULT 'no',
            screenshot_path         TEXT,
            evidence_notes          TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_scan_result(
    url,
    opt_out_found="no",
    opt_out_clicked="no",
    trackers_before_optout="[]",
    trackers_after_optout="[]",
    still_tracking="no",
    screenshot_path=None,
    evidence_notes=None,
):
    """
    Save one scan result to the database.

    Args:
        url:                     The website that was scanned (e.g. "https://example.com").
        opt_out_found:           "yes" or "no" — was an opt-out button found?
        opt_out_clicked:         "yes" or "no" — did we successfully click it?
        trackers_before_optout:  JSON string listing trackers found before opt-out.
        trackers_after_optout:   JSON string listing trackers found after opt-out.
        still_tracking:          "yes" or "no" — were trackers still active after opt-out?
        screenshot_path:         File path to a screenshot taken during the scan.
        evidence_notes:          Any extra notes about what was found.

    Returns:
        The id of the newly inserted row.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO scans (
            url, scan_date, opt_out_found, opt_out_clicked,
            trackers_before_optout, trackers_after_optout,
            still_tracking, screenshot_path, evidence_notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            url,
            datetime.now().isoformat(),
            opt_out_found,
            opt_out_clicked,
            trackers_before_optout,
            trackers_after_optout,
            still_tracking,
            screenshot_path,
            evidence_notes,
        ),
    )

    new_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return new_id


def get_still_tracking():
    """
    Return every scan where trackers were STILL active after the user opted out.

    These are the violations — sites that ignore the user's privacy choice.

    Returns:
        A list of dictionaries, one per matching scan.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row  # lets us access columns by name
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans WHERE still_tracking = 'yes'")
    rows = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return rows


def get_results_for_url(url):
    """
    Return every scan result for a specific website URL.

    Useful for checking a single site's history across multiple scans.

    Args:
        url: The website URL to look up (e.g. "https://example.com").

    Returns:
        A list of dictionaries, one per matching scan.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans WHERE url = ?", (url,))
    rows = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return rows


# ── Quick test ──────────────────────────────────────────────────────
# Run this file directly to verify the database works:
#   python database.py
if __name__ == "__main__":
    print("Initializing database...")
    init_db()

    print("Inserting a test scan...")
    row_id = save_scan_result(
        url="https://example.com",
        opt_out_found="yes",
        opt_out_clicked="yes",
        trackers_before_optout='["google-analytics", "facebook-pixel"]',
        trackers_after_optout='["google-analytics"]',
        still_tracking="yes",
        screenshot_path="screenshots/example.png",
        evidence_notes="Google Analytics remained active after opt-out.",
    )
    print(f"Saved with id={row_id}")

    print("\nAll scans where tracking continued after opt-out:")
    for result in get_still_tracking():
        print(f"  {result['url']} — {result['evidence_notes']}")

    print("\nAll scans for https://example.com:")
    for result in get_results_for_url("https://example.com"):
        print(f"  id={result['id']}  date={result['scan_date']}")

    print("\nDone! Database file: scan_results.db")
