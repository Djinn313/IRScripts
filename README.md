# 🛡️ Incident Response Collection Scripts

**Author:** Mike Sayegh  
**Purpose:** A cross-platform script toolkit for live response, forensic triage, and system data collection during cybersecurity investigations.  
**Platforms:** Windows (PowerShell) & Linux (Bash)  
**Audience:** DFIR professionals, SOC teams, and forensic analysts  
**Permissions:** Requires administrative/root privileges

---

📁 Contents
Script	Language	Platforms	Description
windows-ir.ps1	PowerShell	🪟 Windows	Collects host/network/process/system artifacts
linux-ir.sh	Bash	🐧 Linux	Collects volatile & non-volatile system data
cross_platform_ir.py	Python	🪟 🐧 🍎	Fully interactive IR collector with structured output
ir_collector.go	Go	🪟 🐧 🍎	High-performance CLI IR collector with HTML/ZIP reporting

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
- Root/Sudo privileges
- A local `Tools/` folder with symbolic links or copies of Linux system binaries (e.g., `netstat`, `hostname`, `cp`, etc.)
- Bash-compatible environment

---

### 🐍 Python Script (WIP) (`dfir_collector.py`)

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

### 🦫 Go – Go_IRscript.go

✅ Feature	📝 Description
🔍 Process Listing	Lists running processes
🌐 Network Activity	Captures open connections
🧠 Memory & Disk	Captures RAM + disk usage
🔐 Hashing	SHA-256 for evidence integrity
🔄 Autoruns	Gathers startup items
🔌 USB Devices	Enumerates recent removable media
🧾 Logs	Gathers system logs
🧠 File Access Logs	Pulls auditd / fs_usage or equivalent logs
📄 HTML Report	Generates readable summary
🗜️ ZIP Archive	Optionally compresses all output

🧪 Platform Support:

    ✅ Windows (wmic, wevtutil, schtasks)

    ✅ Linux (journalctl, auditd, /etc/passwd)

    ✅ macOS (log, fs_usage, system_profiler)

⚠️ Run with sudo or Admin rights for full collection
🧰 Requirements

    PowerShell scripts: Windows 10+, Admin rights

    Bash script: Linux with coreutils, ifconfig, netstat, cp

    Python script: Python 3.6+, psutil, cross-platform

    Go script: Go 1.18+, statically compiled binary

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
