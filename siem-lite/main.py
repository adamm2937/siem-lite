"""
SIEM-Lite — Dashboard API & Main Entrypoint
Flask REST API that serves the dashboard and exposes alert/event data.
Run with:  python main.py
"""

import json
import logging
import os
import sys
import threading
from pathlib import Path

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

# ── local imports ─────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

from ingestion.log_ingester import LogIngester
from detection.engine       import DetectionEngine
from alerting.dispatcher    import AlertDispatcher
from storage                import EventStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s — %(message)s",
)
log = logging.getLogger("siem-lite")

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="dashboard")
CORS(app)

store      = EventStore()
dispatcher = AlertDispatcher()


def on_alert(alert):
    store.save_alert(alert)
    dispatcher.dispatch(alert)


engine   = DetectionEngine(alert_callback=on_alert)
ingester = LogIngester(callback=lambda ev: (store.save_event(ev), engine.process(ev)))


# ── API routes ────────────────────────────────────────────────────────────────

@app.get("/api/stats")
def api_stats():
    s = store.stats()
    s.update(engine.stats)
    return jsonify(s)


@app.get("/api/alerts")
def api_alerts():
    limit = min(int(request.args.get("limit", 50)), 500)
    return jsonify(store.recent_alerts(limit=limit))


@app.get("/api/events")
def api_events():
    limit = min(int(request.args.get("limit", 100)), 1000)
    return jsonify(store.recent_events(limit=limit))


@app.get("/api/events/by-type")
def api_events_by_type():
    return jsonify(store.event_counts_by_type())


@app.get("/api/alerts/by-severity")
def api_alerts_by_severity():
    return jsonify(store.alert_counts_by_severity())


# ── dashboard SPA ─────────────────────────────────────────────────────────────

@app.get("/")
def index():
    return send_from_directory("dashboard", "index.html")


# ── entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from flask import request   # import here to avoid circular at module level

    log.info("Starting SIEM-Lite…")
    ingester.start()

    port = int(os.getenv("PORT", 5000))
    log.info("Dashboard → http://localhost:%d", port)
    app.run(host="0.0.0.0", port=port, debug=False)
