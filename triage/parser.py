import json
from pathlib import Path

FIELD_ALIASES = {
	"timestamp": ["timestamp", "TimeCreated"], 
	"event_id": ["event_id", "EventId"], 
	"host": ["host", "Host", "MachineName"], 
	"user": ["user", "SubjectUserName"],
	"process_name": ["process_name", "NewProcessName"], 
	"command_line": ["command_line", "CommandLine"],
	"image_path": ["image_path", "ParentProcessName"], 
	"target_process": ["target_process", "TargetProcessName"], 
	"share_name": ["share_name", "ShareName"], 
	"source_ip": ["source_ip", "SourceIp"],
}


def _first_present(event: dict, keys: list): 
	for key in keys: 
		if key in event and event[key] not in (None, ""):
			return event[key]
	return ""

def _normalise(event: dict) -> dict:
	return {
		field: str(_first_present(event, aliases))
		for field, aliases in FIELD_ALIASES.items()
	}




def parse_json_logs(path: str):
    """Reads a JSON file of raw events and returns a list of normalized events."""
    raw = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if isinstance(raw, dict):
        raw = raw.get("events", raw.get("alerts", []))
    return [_normalise(event) for event in raw]
