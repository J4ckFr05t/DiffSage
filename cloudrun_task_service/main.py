from flask import Flask, request, jsonify
import uuid
import threading
import os
import time
import json
from diff_parser import parse_diff_by_commit
from tasks import format_for_frontend

app = Flask(__name__)
STORE_DIR = "./tasks"
os.makedirs(STORE_DIR, exist_ok=True)

def save_task(task_id, data):
    with open(os.path.join(STORE_DIR, f"{task_id}.json"), "w") as f:
        json.dump(data, f)

def load_task(task_id):
    try:
        with open(os.path.join(STORE_DIR, f"{task_id}.json"), "r") as f:
            return json.load(f)
    except:
        return None

def analyze_background(task_id, payload):
    try:
        save_task(task_id, {"state": "STARTED", "progress": 0})

        pr_data = payload["pr_data"]
        commits = pr_data["commits"]
        google_token = payload.get("google_token")
        prompt_intro = payload.get("prompt_intro")

        # Parse and summarize with progress tracking
        grouped_data = parse_diff_by_commit(
            commits,
            task_id=task_id,
            google_token=google_token,
            prompt_intro=prompt_intro
        )

        summary = {
            "metadata": {
                "title": pr_data["title"],
                "author": pr_data["author"],
                "state": pr_data["state"],
                "url": payload.get("url", "-")
            },
            "commits": format_for_frontend(grouped_data)
        }

        save_task(task_id, {"state": "SUCCESS", "result": summary})
    except Exception as e:
        save_task(task_id, {"state": "FAILURE", "error": str(e)})

@app.route("/analyze", methods=["POST"])
def analyze():
    payload = request.get_json()
    task_id = str(uuid.uuid4())

    save_task(task_id, {"state": "PENDING", "progress": 0})
    thread = threading.Thread(target=analyze_background, args=(task_id, payload))
    thread.start()

    return jsonify({"task_id": task_id})

@app.route("/status/<task_id>", methods=["GET"])
def status(task_id):
    data = load_task(task_id)
    if not data:
        return jsonify({"error": "Task not found"}), 404
    return jsonify(data)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)