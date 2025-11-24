# Shinobi-Threat-Hunt

<img width="1332" height="808" alt="image" src="https://github.com/user-attachments/assets/057cecd1-7556-4240-b978-1ec0ebf6c4a6" />




A guided SOC investigation using Microsoft Defender for Endpoint and Sentinel. This project walks through a full threat-hunting workflow — from hypothesis building to KQL enrichment, IOC mapping, MITRE alignment, and final incident reporting — based entirely on real telemetry from a simulated enterprise attack. Designed to strengthen practical SOC analysis, methodology, and documentation skills.
🚀 Shinobi Threat-Hunting Lab — Microsoft Defender for Endpoint

📌 Table of Contents

Overview

Objectives

Lab Architecture

Tools & Technologies

MITRE ATT&CK Mapping

Threat Scenario Summary

Hunting Methodology

KQL Queries

Findings & Analysis

Final Report

How to Reproduce This Lab

Author

🧭 Overview

The Shinobi Threat-Hunting Lab is a full end-to-end investigation built using Microsoft Defender for Endpoint (MDE).
It simulates attacker behaviour such as:

Host reconnaissance

Credential harvesting (LSASS)

Privilege escalation

Lateral movement via cmdkey + mstsc

Data staging

This project is part of my SOC Analyst & Detection Engineering portfolio, demonstrating my ability to hunt adversaries using real telemetry, KQL, and MITRE ATT&CK mapping.

🎯 Objectives

Detect attacker activity using Advanced Hunting (KQL)

Rebuild a complete incident timeline

Identify Indicators of Attack (IOA) and Indicators of Compromise (IOC)

Correlate telemetry across multiple Defender tables

Apply MITRE ATT&CK techniques to each malicious action

Produce a Top Tier threat-hunting report

🏛️ Lab Architecture
Attacker Machine (Windows/Kali)
    ├─ Reconnaissance
    ├─ Credential Dumping
    ├─ RDP Lateral Movement
    └─ Data Staging

Victim Endpoint (Windows 10/11)
    ├─ Microsoft Defender for Endpoint Sensor
    ├─ Logging enabled
    └─ Controlled malicious activity executed

Microsoft 365 Defender Portal
    ├─ Advanced Hunting (KQL)
    ├─ Incident console
    ├─ Entity timelines
    └─ Alert correlation


Optional tools:

Sysinternals Suite

Sysmon

Event Viewer

Wireshark (optional traffic analysis)

🛠️ Tools & Technologies

Microsoft Defender for Endpoint

Kusto Query Language (KQL)

Microsoft 365 Defender Advanced Hunting

MITRE ATT&CK Framework

PowerShell / CMD

Sysinternals

Virtual machines or sandboxes

🗡️ MITRE ATT&CK Mapping
Stage	Description	MITRE ID
Discovery	System and network recon	T1082, T1016
Credential Access	LSASS memory dump	T1003.001
Persistence	Run keys / registry	T1547
Lateral Movement	RDP with stolen credentials	T1021.001
Defense Evasion	Use of legitimate Windows binaries	T1036
Collection	Data staging	T1074
Command & Control	Protocol misuse	T1071
🧨 Threat Scenario Summary

The lab simulates a stealthy attacker (the “Shinobi”) who:

Enumerates host and environment information

Dumps LSASS to extract credentials

Creates credential entries using cmdkey.exe

Initiates lateral movement using mstsc.exe

Connects to a secondary device

Stages sensitive data for exfiltration

Your mission: detect, analyze, correlate, and document.

🔍 Hunting Methodology

A structured threat-hunting approach:

1. Baseline

Understand normal behaviour for processes and accounts.

2. Pivoting

Pivot between:

DeviceProcessEvents

DeviceNetworkEvents

DeviceLogonEvents

DeviceRegistryEvents

3. Correlation

Link suspicious activity by:

Timestamps

Account name

Device name

Parent processes

4. MITRE Mapping

Classify each malicious behaviour into ATT&CK categories.

5. Reporting

Summarize findings and write a complete hunting report.

📡 KQL Queries
🔎 Reconnaissance
DeviceProcessEvents
| where ProcessCommandLine has_any ("systeminfo", "hostname", "net user")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName

🧪 Credential Access (LSASS Dump)
DeviceProcessEvents
| where ProcessCommandLine has "lsass"
| where ProcessCommandLine has_any ("procdump", ".dmp")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName

🛂 Credential Injection (cmdkey)
DeviceProcessEvents
| where FileName == "cmdkey.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

🖥️ Lateral Movement (mstsc)
DeviceProcessEvents
| where FileName =~ "mstsc.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

🌐 RDP Connection Events
DeviceNetworkEvents
| where RemotePort == 3389
| summarize count() by DeviceName, RemoteIP, bin(Timestamp, 1h)


📝 Findings & Analysis

This section contains:

A breakdown of every attacker action

How it was detected

Which logs confirmed the behaviour

Why the action is malicious

MITRE mapping for each technique



🔥 Final Report

📄 Access the full Shinobi Threat-Hunting Report:
➡️ /reports/Shinobi-Threat-Hunting-Report.pdf
➡️ /reports/Shinobi-Threat-Hunting-Report.md


🧪 How to Reproduce This Lab

Deploy two Windows VMs (attacker + victim)

Enable MDE sensor on victim machine

Execute attacker commands (provided in the report)

Collect telemetry in Microsoft 365 Defender

Use KQL to reconstruct the kill chain

Document all findings

This allows SOC analysts to practice real-world incident investigation.



Pedro Fernandes Parreira
Cybersecurity Analyst | Defensive Security | SOC & Threat Hunting
🔗 GitHub: github.com/pedro33parreira
