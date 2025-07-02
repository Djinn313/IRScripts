# 🛡️ Incident Response Collection Scripts

**Author:** Mike Sayegh  
**Purpose:** A cross-platform script toolkit for live response, forensic triage, and system data collection during cybersecurity investigations.  
**Platforms:** Windows (PowerShell) & Linux (Bash)  
**Audience:** DFIR professionals, SOC teams, and forensic analysts  
**Permissions:** Requires administrative/root privileges

---

## 📁 Overview

This repository contains two scripts designed to collect volatile and non-volatile system data during an active incident:

- `windows_ir.ps1`: A PowerShell script for gathering a wide range of Windows forensic artifacts.
- `linux_ir.sh`: A Bash script for collecting key Linux forensic artifacts via a guided terminal interface.

These tools are designed to preserve relevant data in a structured format for post-collection analysis, timeline reconstruction, and threat hunting.

---

## 🖥️ Script Details

### 🔹 `windows_ir.ps1` (PowerShell - Windows)

**Artifacts Collected:**
- System info (hostname, user, network adapters)
- Running processes and services
- Network connections and neighbors
- DNS cache
- Hotfixes and event logs
- Recently modified files and installed programs
- Scheduled tasks and startup programs
- Group Policy Objects (if joined to a domain)

**Output Format:**
- CSV, TXT, and HTML files in a folder named `IR results` on the Desktop.

**Requirements:**
- PowerShell 5.1+
- Run as Administrator
- If domain-joined and `GroupPolicy` module is available, `Get-GPOReport` will run.

---

### 🔹 `linux_ir.sh` (Bash - Linux)

**Features:**
- Interactive prompt to collect investigator info and case metadata
- Automatically creates a collection folder and saves outputs
- Captures:
  - System date/time
  - Logged-in users
  - Netstat, SS, and dmesg output
  - Network interfaces
  - Recursive directory listing (`/`)
  - Copies `/etc/passwd` and `/var/log`
  - Dumps shell environment variables

**Requirements:**
- Root privileges
- A local `Tools/` folder with symbolic links or copies of Linux system binaries (e.g., `netstat`, `hostname`, `cp`, etc.)
- Bash-compatible environment

---

### 🐍 3. Python Script (`dfir_collector.py`)

- **Platform:** Cross-platform (Windows, Linux, macOS)  
- **Purpose:** Comprehensive evidence collection tool capturing volatile data (processes, network connections, logged-in users, memory info), system configuration, environment variables, and OS-specific logs (Windows event logs, Linux syslogs, macOS unified logs).  
- **Features:**  
  - Interactive case and investigator metadata input 📝  
  - Structured directory output separating volatile, non-volatile, logs, memory, network, and system data 📁  
  - Detailed logging of collection steps 📜  
  - SHA-256 hashing of collected files with a final JSON evidence report 🔒  
- **Usage:** Run with **Administrator/root** privileges recommended.  
- **Output:** Timestamped evidence folder with organized artifacts and reports.

---

## ⚠️ Notes

- **Run with elevated privileges** (`Administrator` on Windows, `root` or `sudo` on Linux) for full access to system data.
- Scripts are intended for **incident response and evidence preservation**, not remediation.
- Output should be secured, hashed, and backed up as part of chain-of-custody procedures if used in legal contexts.

---

## 📝 License

Free to use, modify, and distribute with attribution.  

---

## ✨ Bonus

> “UNLIMITED POWAAAAAAA!” — *Papa Palp*  
> _(Embedded in the Windows script as your forensic hype man)_

---
