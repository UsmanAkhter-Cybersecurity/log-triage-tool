# 🔧 Log Triage Tool — Custom Python Security Automation 


**A custom Python log analysis and detection tool for identifying post-exploitation credential-dumping activity in Windows Security event logs.**

---

📌 **Executive Summary**

A lightweight, YAML-driven detection engine that parses Windows Event ID 
4688 (Process Creation) telemetry and flags known credential-harvesting 
tools. Built and validated in a controlled lab environment — attacks were 
executed on a Windows 10 VM., captured via native Windows auditing, 
and processed through the tool's normalization and rule-matching pipeline 
to confirm real-world detection capability.

🛠️ **Core Competencies & Methodology**

- **Telemetry Normalization:** Built a field-aliasing layer to translate 
  inconsistent raw Windows event field names (`NewProcessName`, 
  `CommandLine`, etc.) into a stable internal schema, verified against 
  real `Get-WinEvent` output rather than assumed field names.
- **Detection Engineering:** Authored YAML-based detection rules using 
  regex, exact-match, and contains-match logic, with MITRE ATT&CK 
  technique mapping (T1003, T1555) and severity scoring.
- **Validated Detection:** Confirmed the tool correctly flags real 
  execution of **LaZagne** and **Mimikatz** — both run live in an 
  isolated lab VM, with logs captured via native Windows Security 
  auditing (command-line logging enabled) and processed end-to-end.

📁 **Repository Contents**

- `script.py` — CLI entry point
- `triage/parser.py` — normalizes raw log events into internal schema
- `triage/rules_engine.py` — YAML rule loading and event scoring
- `rules.yaml` — detection rule definitions
- `sample_logs/` — sanitized real and synthetic test data

🔍 **Verification & Testing**
<img width="1456" height="819" alt="preview" src="https://github.com/user-attachments/assets/2bccba5d-4eb8-4cad-bf3e-46f24365e1be" />

The tool was validated against live-captured telemetry, not synthetic 
data alone:
- **LaZagne execution** — correctly flagged via process name and 
  command-line module arguments
- **Mimikatz LSASS credential dumping** — correctly flagged via process 
  name, scored as CRITICAL severity

---

💡 *Developed by Usman Akhter 
