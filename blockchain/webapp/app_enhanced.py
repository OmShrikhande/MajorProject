# webapp/app_enhanced.py
from flask import Flask, request, jsonify
from blockchain_client import log_biometric_event, read_log, sha256_hex_of_json
import os

app = Flask(__name__)

# Public read endpoint
@app.route("/api/logs", methods=["GET"])
def list_logs():
    total = contract.functions.totalLogs().call()
    out = []
    for i in range(total):
        out.append(read_log(i))
    return jsonify(out), 200

# Get single
@app.route("/api/logs/<int:index>", methods=["GET"])
def get_log(index):
    return jsonify(read_log(index)), 200

# Create log (write). Protect this endpoint!
@app.route("/api/logs", methods=["POST"])
def create_log():
    # SIMPLE auth example (use JWT or API keys in prod)
    api_key = request.headers.get("x-api-key")
    if api_key != os.getenv("API_WRITE_KEY"):
        return jsonify({"error": "unauthorized"}), 401

    data = request.json
    user_internal_id = data["user_internal_id"]
    event_type = data["event_type"]  # e.g., 0..3
    meta = data["meta"]

    # Save meta off-chain (DB) here — ensure canonical JSON and store
    # db.save(meta)  <-- implement DB logic

    # Compute meta hash and send tx
    receipt = log_biometric_event(user_internal_id, event_type, meta)
    return jsonify({"tx_hash": receipt.transactionHash.hex(), "status": "submitted"}), 202

# Verify integrity: recompute DB JSON hash and compare to on-chain
@app.route("/api/logs/<int:index>/verify", methods=["GET"])
def verify_log(index):
    # Load meta JSON from DB for this index (implement your DB mapping)
    # db_meta = db.get_meta_by_index(index)
    db_meta = {}  # placeholder
    recomputed = sha256_hex_of_json(db_meta)
    onchain = read_log(index)["meta_hash"]
    return jsonify({"match": ("0x"+recomputed)==onchain}), 200
