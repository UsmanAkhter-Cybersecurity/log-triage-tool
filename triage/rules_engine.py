import re
import yaml 


SEVERITY_THRESHOLDS = [ 
	(9, "critical"),
	(6, "high"),
	(3, "medium"), 
	(0, "low"), 

] 


def load_rules(path: str) -> list: 

	with open(path, 'r') as f: 
		rules = yaml.safe_load(f)


	required_keys = {"id", "description", "event_field", "match_type", "match_type", "pattern", "severity"}
	valid_match_types = {"equals", "contains", "regex"}


	for rule in rules: 
		missing = required_keys  - set(rule.keys())
		if missing:
			raise ValueError(f"Rule {rule.get('id', 'UNKNOWN')} is missing keys: {missing}")

		if rule["match_type"] not in valid_match_types:
			raise ValueError(
				f"Rule {rule['id']} has invalid match_type '{rule['match_type']}'."
				f"Must be one of: {valid_match_types}"
			)
	return rules 



def _rule_matches(rule: dict, event: dict) -> bool: 

	value = str(event.get(rule["event_field"], "") or "")
	pattern = str(rule["pattern"])

	if rule["match_type"] == "equals": 
		return value.lower() == pattern.lower()

	elif rule["match_type"] == "contains":
		return pattern.lower() in value.lower()


	elif rule["match_type"] == "regex": 
		try:
			return re.search(pattern, value) is not None 
		except re.error: 
			return False







def evaluate(events: list, rules: list) -> list: 


	enriched_events = [] 

	for event in events:
		matched_rules = []
		cumulative_score = 0

		for rule in rules:
			if _rule_matches(rule, event):
				matched_rules.append(rule)
				cumulative_score += rule["severity"]

		event_copy = event.copy()
		event_copy["matched_rules"] = [r["id"] for r in matched_rules]
		event_copy["score"] = cumulative_score 


		event_copy["severity"] = "low"
		for threshold, label in SEVERITY_THRESHOLDS: 
			if cumulative_score >= threshold: 
				event_copy["severity"] = label 
				break 

		enriched_events.append(event_copy)


	return enriched_events



