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


	required_keys = {"id", "description", "event_field", "match_type"}
