# Homelab SOC SIEM - Live Attacker Detection with Microsoft Sentinel

![Azure](https://img.shields.io/badge/Microsoft%20Azure-Cloud%20Security-blue)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-SIEM-purple)
![KQL](https://img.shields.io/badge/KQL-Threat%20Hunting-orange)
![SOC](https://img.shields.io/badge/SOC-Lab-green)
![Status](https://img.shields.io/badge/Status-Completed-success)

## Project Overview
<img width="940" height="519" alt="image" src="https://github.com/user-attachments/assets/0df15bff-0b45-4538-9373-e20ff61124a4" />
This project demonstrates the design and implementation of a cloud-based Security Operations Centre (SOC) home lab using Microsoft Azure, Microsoft Sentinel, Log Analytics Workspace, Azure Monitor Agent (AMA), Data Collection Rules (DCR), KQL and GeoIP enrichment.
An intentionally exposed Windows honeypot was deployed to generate authentication telemetry. Failed authentication events were collected centrally and investigated through Microsoft Sentinel. Event ID 4625 was used as the primary detection signal for suspicious login activity.
The investigation was extended by enriching attacker IP addresses with geographic information through a Sentinel Watchlist.
> **Portfolio objective:** demonstrate practical SOC capabilities across telemetry collection, SIEM monitoring, detection engineering, KQL investigation, IOC analysis, enrichment and incident triage.

---

## Objectives
- Deploy an Azure Windows honeypot
- Generate and observe failed authentication activity
- Centralise Windows Security Events
- Configure Microsoft Sentinel as the SIEM
- Collect telemetry using Azure Monitor Agent
- Configure a Data Collection Rule
- Investigate Event ID 4625 using KQL
- Identify high-volume source IP addresses
- Enrich IP addresses using GeoIP data
- Develop a brute-force detection query
- Produce a SOC-style incident investigation report

---

## Steps
1. Navigate to https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account
  and create Free Azure Subscription
2. After the subscription is created, login at: https://portal.azure.com
3. Create a new Windows Server Honey Pot (Azure Virtual Machine)
4. Navigate to the Network Security Group on the newly created virtual machine and create a rule that allows all traffic inbound
5. Log into the virtual machine and turn off the windows firewall (start -> wf.msc -> properties -> all off)
6.  Logging into the VM and inspecting logs
7. Make a Fail 3 logins as “employee” (or some other username)
8. Login to the virtual machine
9. Open up Event Viewer and inspect the security logs
10. Observe the three failed logins as “employee”, event ID 4625
11. Create Log Analytics Workspace
12. Create a Sentinel Instance and connect it to Log Analytics
13. Configure the “Windows Security Events via AMA” connector
14. Create the DCR within sentinel, watch for extension creation
15. Query logs within the Log analytics workspace as well as the SIEM
16. Observe some of the VM logs:
             - SecurityEvent
             -  | where EventId == 4625
17.  Check SecurityEvent logs in the Log Analytics Workspace
18. Import a spreadsheet (as a “Sentinel Watchlist”) which contains geographic information for each block of IP addresses.

19. Within Sentinel, create the watchlist:
- Name/Alias: geoip
- Source type: Local File
- Number of lines before row: 0
-Search Key: network

20. Observe the logs now have geographic information, so you can see where the attacks are coming from
- let GeoIPDB_FULL = _GetWatchlist("geoip");
- let WindowsEvents = SecurityEvent
- | where IpAddress == <attacker IP address>
- | where EventID == 4625
- | order by TimeGenerated desc
- | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
 - WindowsEvents

21. Within Sentine, create a new Workbook
22. Delete the prepopulated elements and add a “Query” element
23. Go to the advanced editor tab, and paste the JSON
- Workbook (Attack map):
- map.json

24. Observe the query
25. Observe the map settings
26. Observe the map
-------------

## Architecture
```text
                         INTERNET
                            │
                            ▼
                    ┌──────────────┐
                    │  Test/Threat │
                    │    Source    │
                    └──────┬───────┘
                           │
                  Failed Authentication
                           │
                           ▼
              ┌─────────────────────────┐
              │ Azure Windows Honeypot  │
              │          VM             │
              └────────────┬────────────┘
                           │
                    Windows Events
                           │
                           ▼
              ┌─────────────────────────┐
              │ Azure Monitor Agent    │
              │          AMA            │
              └────────────┬────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │ Data Collection Rule    │
              │          DCR            │
              └────────────┬────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │ Log Analytics Workspace │
              │          LAW            │
              └────────────┬────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │   Microsoft Sentinel    │
              │          SIEM           │
              └────────────┬────────────┘
                           │
                     KQL Investigation
                           │
                           ▼
              ┌─────────────────────────┐
              │ GeoIP Sentinel          │
              │ Watchlist Enrichment    │
              └────────────┬────────────┘
                           │
                           ▼
                  Attacker Location /
                  Investigation Context
```
---

## Technology Stack
- Technology	Role
- Microsoft Azure	Cloud infrastructure
- Windows VM	Honeypot / telemetry source
- Network Security Group	Network exposure/control
- Windows Event Viewer	Local event validation
- Azure Monitor Agent	Telemetry collection
- Data Collection Rule	Collection configuration
- Log Analytics Workspace	Central log repository
- Microsoft Sentinel	SIEM and detection platform
- KQL	Investigation and detection
- Sentinel Watchlist	GeoIP enrichment
 
---

Detection Scenario
Primary Detection
Event ID 4625 — Failed Logon
The honeypot generated failed authentication events. These events were collected into Log Analytics and investigated through Microsoft Sentinel.
Key investigation fields:
`TimeGenerated`
`Account`
`IpAddress`
`Computer`
`LogonType`
`EventID`
Basic Detection Query
```kql
SecurityEvent
| where EventId == 4625
| order by TimeGenerated desc
```
Top Source IPs
```kql
SecurityEvent
| where EventId == 4625
| summarize FailedAttempts = count() by IpAddress
| order by FailedAttempts desc
```
Source IP Investigation
```kql
SecurityEvent
| where IpAddress == "<ATTACKER_IP>"
| where EventId == 4625
| project TimeGenerated, Account, IpAddress, Computer, LogonType
| order by TimeGenerated desc
```
---

🌍 GeoIP Enrichment
A Sentinel Watchlist named `geoip` was used to enrich source IP addresses with geographic context.
```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");

let WindowsEvents =
    SecurityEvent
    | where IpAddress == "<ATTACKER_IP>"
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(
        GeoIPDB_FULL,
        IpAddress,
        network
    );

WindowsEvents
```
## Investigation Value
- GeoIP enrichment helps an analyst move from: Raw IP → Network → Geographic Context → Investigation
- Geographic information should be treated as contextual intelligence rather than proof of an attacker's physical location.

---

Detection Rule
The following query can form the basis of a Sentinel Analytics Rule for repeated failed authentication attempts:
```kql
SecurityEvent
| where EventID == 4625
| summarize
    FailedAttempts = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by IpAddress
| where FailedAttempts >= 10
| order by FailedAttempts desc
```

Suggested SOC Triage
- When triggered:
- Validate the source IP.
- Review the number and timing of failures.
- Identify targeted accounts.
- Check for successful authentication after failures.
- Review logon type and target host.
- Enrich the IP using threat intelligence/GeoIP.
- Determine whether the activity resembles brute force or password spraying.
- Document the investigation.
- Apply containment where appropriate.

---

## Evidence Gallery
- Evidence	Screenshot
- Azure VM	`screenshots/01-azure-vm.png`
- Network Security Group	`screenshots/02-network-security-group.png`
- Event ID 4625	`screenshots/03-event-viewer-4625.png`
- Log Analytics Workspace	`screenshots/04-log-analytics-workspace.png`
- Microsoft Sentinel	`screenshots/05-microsoft-sentinel.png`
- AMA Connector	`screenshots/06-ama-connector.png`
- DCR	`screenshots/07-dcr.png`
- KQL Investigation	`screenshots/08-kql-query.png`
- Attacker IP	`screenshots/09-attacker-ip.png`
- GeoIP Enrichment	`screenshots/10-geoip-enrichment.png`
- Sentinel Alert	`screenshots/11-sentinel-alert.png`
---

## SOC Investigation Workflow
```text

COLLECT
   ↓
DETECT
   ↓
TRIAGE
   ↓
INVESTIGATE
   ↓
ENRICH
   ↓
CORRELATE
   ↓
ASSESS
   ↓
RESPOND
   ↓
DOCUMENT
```

---

 ## Skills Demonstrated
![Security Operations](https://img.shields.io/badge/Security-Security%20Operations-0075ca?style=flat-square)
![SIEM Monitoring](https://img.shields.io/badge/SIEM-SIEM%20Monitoring-0075ca?style=flat-square)
![Alert Triage](https://img.shields.io/badge/SOC-Alert%20Triage-0075ca?style=flat-square)
![Authentication Investigation](https://img.shields.io/badge/Investigation-Authentication%20Investigation-e36209?style=flat-square)
![IOC Analysis](https://img.shields.io/badge/Threat-IOC%20Analysis-e36209?style=flat-square)
![Log Analysis](https://img.shields.io/badge/Technical-Log%20Analysis-586069?style=flat-square)
![Threat Detection](https://img.shields.io/badge/Detection-Threat%20Detection-e36209?style=flat-square)
![Incident Documentation](https://img.shields.io/badge/SOC-Incident%20Documentation-0075ca?style=flat-square)
![Microsoft Security](https://img.shields.io/badge/Microsoft-Microsoft%20Security-0078d4?style=flat-square)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft-Microsoft%20Sentinel-0078d4?style=flat-square)
![Log Analytics](https://img.shields.io/badge/Azure-Log%20Analytics-0078d4?style=flat-square)
![Azure Monitor Agent](https://img.shields.io/badge/Azure-Azure%20Monitor%20Agent-0078d4?style=flat-square)
![Data Collection Rules](https://img.shields.io/badge/Azure-Data%20Collection%20Rules-0078d4?style=flat-square)
![Sentinel Watchlists](https://img.shields.io/badge/Sentinel-Sentinel%20Watchlists-0078d4?style=flat-square)
![Detection Engineering](https://img.shields.io/badge/Engineering-Detection%20Engineering-6f42c1?style=flat-square)
![KQL Filtering](https://img.shields.io/badge/KQL-KQL%20Filtering-6f42c1?style=flat-square)
![Aggregation](https://img.shields.io/badge/KQL-Aggregation-6f42c1?style=flat-square)
![Threshold-based Detection](https://img.shields.io/badge/Detection-Threshold--based%20Detection-e36209?style=flat-square)
![Source IP Analysis](https://img.shields.io/badge/Analysis-Source%20IP%20Analysis-586069?style=flat-square)
![GeoIP Enrichment](https://img.shields.io/badge/Analysis-GeoIP%20Enrichment-586069?style=flat-square)
![Cloud Security](https://img.shields.io/badge/Cloud-Cloud%20Security-0e7490?style=flat-square)
![Azure VM Deployment](https://img.shields.io/badge/Azure-Azure%20VM%20Deployment-0078d4?style=flat-square)
![Network Security Groups](https://img.shields.io/badge/Azure-Network%20Security%20Groups-0078d4?style=flat-square)
![Cloud Logging](https://img.shields.io/badge/Cloud-Cloud%20Logging-0e7490?style=flat-square)
![Cloud SIEM Architecture](https://img.shields.io/badge/Architecture-Cloud%20SIEM%20Architecture-6f42c1?style=flat-square)

---
📁 Repository Structure
```text
homelab-soc-siem/
├── README.md
├── architecture/
│   └── soc-architecture.png
├── documentation/
│   ├── deployment.md
│   ├── log-collection.md
│   └── investigation.md
├── kql/
│   ├── failed-logins.kql
│   ├── top-attacker-ips.kql
│   ├── attacker-investigation.kql
│   └── geoip-enrichment.kql
├── detection-rules/
│   └── brute-force-detection.kql
├── incident-reports/
│   └── sample-incident-report.md
└── screenshots/
```
---

## Key Findings
- Total failed authentication events: [INSERT VALUE]
- Most active source IP: [REDACTED / INSERT VALUE]
- Highest failed-attempt count: [INSERT VALUE]
- Targeted account(s): [INSERT VALUE]
- Observed attack window: [INSERT VALUE]
- GeoIP context: [INSERT VALUE]
- Initial assessment: [BRUTE FORCE / PASSWORD SPRAYING / OTHER]

---

## Security & Cost Disclaimer
This project is intended for educational and defensive security research.
The honeypot is intentionally exposed for telemetry generation and must remain isolated from production systems.
Do not store sensitive data, personal credentials, secrets, production workloads or confidential information on the honeypot.
Azure resources can generate charges. Stop/deallocate or remove resources when the lab is not in use.

---

##  Contact

If you have questions about this project or would like to discuss vulnerability management, Nessus, or cybersecurity more broadly:

- 🔗 **GitHub:** [@oluwaseunadenuga](https://github.com/oluwaseunadenuga)
- 💼 **LinkedIn:** [linkedin.com/in/oluwaseunadenuga](https://linkedin.com/in/oluwaseunadenuga)
- 📧 **Email:** Available via LinkedIn

---

<div align="center">

---
Add your SOC architecture diagram here as `soc-architecture.png`.
