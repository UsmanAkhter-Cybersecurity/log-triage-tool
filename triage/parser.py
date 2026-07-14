import json
from pathlib import Path


def _normalise(event: dict) -> dict:
    """Takes a raw JSON event and standardizes it to our internal schema."""
    return {
        "timestamp": event.get("timestamp", ""),
        "event_id": str(event.get("event_id", "")),
        "host": event.get("host", "unknown-host"),
        "user": event.get("user", "unknown-user"),
        "process_name": event.get("process_name", ""),
        "command_line": event.get("command_line", ""),
        "image_path": event.get("image_path", ""),
        "target_process": event.get("target_process", ""),
        "share_name": event.get("share_name", ""),
        "source_ip": event.get("source_ip", "")
    }

def parse_json_logs(path: str):
    """Reads a JSON file of raw events and returns a list of normalized events."""
    raw = json.loads(Path(path).read_text())
    if isinstance(raw, dict):
        raw = raw.get("events", raw.get("alerts", []))
    return [_normalise(event) for event in raw]
