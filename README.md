# Threat Hunt Report — Azuki Import/Export Espionage Case
### Cyber Range Incident Investigation | November 2025

---

## Incident Brief

### Organisation

<img width="597" height="902" alt="image" src="https://github.com/user-attachments/assets/5c1ac1d3-0a5e-4e13-91bd-3831aacbdced" />

Azuki Import / Export Trading Co.  
23 employees | Shipping logistics (Japan & Southeast Asia)

### Situation
A competitor undercut Azuki’s 6-year shipping contract by exactly 3%.  
Soon after, **internal supplier contracts and pricing documents appeared on underground forums**.

### Compromised System
- Hostname: AZUKI-SL  
- Role: IT Administrator Workstation  

### Evidence Available
- Microsoft Defender for Endpoint telemetry

---

## Investigation Objectives

- Identify initial access method  
- Identify compromised account(s)  
- Determine what data was stolen  
- Identify exfiltration method  
- Confirm persistence mechanisms  

---

## IOC Summary

| Indicator | Value |
|-----------|------|
| Host | AZUKI-SL |
| Compromised Account | Administrator |
| Access Vector | RDP |
| Persistence | Registry Run Key |
| Exfiltration | HTTPS outbound |
| Impact | Confidential data leak |
| Threat Type | Corporate espionage |

---

## Investigation Queries

### Initial Access Detection

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName == "mstsc.exe"
| or ProcessCommandLine has "3389"

