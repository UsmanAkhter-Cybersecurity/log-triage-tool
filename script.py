import os
import json
import argparse
from triage.parser import parse_json_logs
from triage.rules_engine import load_rules, evaluate

def main():
    # Set up argument parsing so flags like --rules work seamlessly
    parser = argparse.ArgumentParser(description="Log Triage Tool")
    parser.add_argument("--rules", default="rules.yaml", help="Path to YAML rules file")
    parser.add_argument("--logs", default="sample_logs", help="Path to logs directory")
    args = parser.parse_args()

    print("————— LOG TRIAGE TOOL: ACTIVE —————")

    # 1. Load the security rules
    if not os.path.exists(args.rules):
        print(f"Error: Rules file '{args.rules}' does not exist.")
        return
    rules = load_rules(args.rules)

    # 2. Target the structured JSON logs in the directory
    if not os.path.exists(args.logs):
        print(f"Error: Log file '{args.logs}' not found.")
        return

    print(f"\n[Analyzing] {args.logs}")
    print("-" * 40)
    events = parse_json_logs(args.logs)
    # 4. Run the data through your rules engine!
    enriched_events = evaluate(events, rules)

    # 5. Output any alerts that triggered a match
    alerts_found = False
    for event in enriched_events:
        if event.get("score", 0) > 0:
            alerts_found = True
            print(f"🚨 ALERT [{event.get('severity', 'UNKNOWN').upper()}] (Score: {event.get('score', 0)})")
            print(f"  Matched Rules: {', '.join(event.get('matched_rules', []))}")
            print(f"  Event Details: {json.dumps(event, indent=2)}")
            print("-" * 40)

    if not alerts_found:
        print("Scan complete. No rules triggered.")

if __name__ == "__main__":
    main()

