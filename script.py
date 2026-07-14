import os 

LOG_DIR = "sample_logs"


print("----- LOG TRIAGE TOOL: ACTIVE -----")

if not os.path.exists(LOG_DIR):
	print(f"Error: The directory '{LOG_DIR}' does not exist.")
else:

	files = os.listdir(LOG_DIR)
	log_files = [f for f in files if f.endswith('.log') or f.endswith('.txt')]

	print(f"Scanning directory '{LOG_DIR}'... Found {len(log_files)} log files.")

	for file_name in log_files:
		file_path = os.path.join(LOG_DIR, file_name)
		print(f"\n[Analyzing] {file_name}")
		print("-" * 40)
		
		with open(file_path, 'r') as file:
			for line_num, line in enumerate(file, 1): 

				if "failed" in line.lower() or 'error' in line.lower():
					print(f" Line {line_num}: {line.strip()}")
