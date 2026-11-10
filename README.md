# SOC Log Analyzer 🛡️

## Overview
This is a Python-based security tool designed to automate the initial triage of server logs. It simulates a common Security Operations Center (SOC) task: detecting brute-force login attempts and extracting malicious IP addresses for blocking.

## Features
- Automates the parsing of server log files.
- Identifies `FAILED LOGIN` events indicating potential unauthorized access.
- Extracts and isolates the originating IP addresses.
- Filters duplicate IPs to create a clean, actionable blocklist.

## Skills Demonstrated
- **Python Programming:** Loops, conditional statements, string manipulation, and list operations.
- **Security Operations:** Log analysis, threat identification, and automation of repetitive SOC tasks.

## How to Run
1. Open the terminal.
2. Run the script using Python 3:
   ```bash
   python3 log_analyzer.py
Author: Cybersecurity Student @ TU Sofia
