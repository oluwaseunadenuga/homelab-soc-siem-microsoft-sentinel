# Homelab SOC SIEM — Microsoft Sentinel & Microsoft Defender

![Azure](https://img.shields.io/badge/Microsoft%20Azure-Cloud%20Security-blue)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-SIEM-purple)
![KQL](https://img.shields.io/badge/KQL-Threat%20Hunting-orange)
![SOC](https://img.shields.io/badge/SOC-Lab-green)
![Status](https://img.shields.io/badge/Status-Completed-success)

<img width="940" height="529" alt="Microsoft Sentinel SOC lab overview" src="https://github.com/user-attachments/assets/ca59d82e-c803-4102-9694-9ea1fcf87e08" />

## Project Overview

This project demonstrates the design and implementation of a cloud-based Security Operations Centre (SOC) home lab using Microsoft Azure, Microsoft Sentinel, Log Analytics Workspace, Azure Monitor Agent (AMA), Data Collection Rules (DCR), KQL and GeoIP enrichment.

An intentionally exposed Windows honeypot was deployed in an isolated lab environment to generate authentication telemetry. Failed authentication events were collected centrally and investigated through Microsoft Sentinel. Windows Event ID **4625** was used as the primary detection signal for suspicious failed logon activity.

The investigation was extended by enriching source IP addresses with geographic context using a Microsoft Sentinel Watchlist and presenting the results through KQL-based visualisation.

> **Lab safety:** This is an educational defensive-security lab. The honeypot should be isolated from production systems and must not contain sensitive information, production credentials or confidential data.

---

## Objectives

- Deploy an Azure Windows honeypot for security telemetry generation.
- Configure Azure networking and Network Security Group controls.
- Validate Windows Security Event ID 4625 locally.
- Centralise Windows security telemetry in Log Analytics.
- Configure Microsoft Sentinel as the SIEM platform.
- Configure Azure Monitor Agent (AMA) and a Data Collection Rule (DCR).
- Investigate failed authentication activity using KQL.
- Identify high-volume source IP addresses.
- Enrich IP addresses using a Sentinel GeoIP Watchlist.
- Develop a threshold-based brute-force detection query.
- Perform IOC and source-IP analysis.
- Visualise failed logon activity geographically.
- Document findings in a SOC-style investigation.

---

## Architecture

```text
                         INTERNET
                            │
                            ▼
                 ┌─────────────────────┐
                 │  Test / Threat      │
                 │      Source         │
                 └──────────┬──────────┘
                            │
                   Failed Authentication
                            │
                            ▼
              ┌─────────────────────────┐
              │  Azure Windows Honeypot │
              │           VM            │
              └────────────┬────────────┘
                           │
                    Windows Security
                        Events
                           │
                           ▼
              ┌─────────────────────────┐
              │   Azure Monitor Agent   │
              │          AMA            │
              └────────────┬────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │   Data Collection Rule  │
              │          DCR            │
              └────────────┬────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │   Log Analytics         │
              │      Workspace           │
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
              │ Sentinel GeoIP          │
              │ Watchlist Enrichment    │
              └────────────┬────────────┘
                           │
                           ▼
                 Investigation Context
                 / Attack Map
```

---

## Technology Stack

| Technology | Role |
|---|---|
| Microsoft Azure | Cloud infrastructure |
| Azure Virtual Network | Network infrastructure |
| Windows Server VM | Honeypot / telemetry source |
| Network Security Group | Network exposure and access control |
| Windows Event Viewer | Local event validation |
| Azure Monitor Agent | Telemetry collection |
| Data Collection Rule | Telemetry collection configuration |
| Log Analytics Workspace | Central log repository |
| Microsoft Sentinel | SIEM, detection and investigation |
| KQL | Detection, investigation and threat hunting |
| Sentinel Watchlist | GeoIP enrichment |
| Microsoft Defender for Endpoint | Advanced hunting and endpoint telemetry |
| Sentinel Workbook | Data visualisation and attack-map presentation |

---

## Lab Implementation

### 1. Azure Environment

1. Create an Azure subscription suitable for the lab.
2. Sign in to the [Azure Portal](https://portal.azure.com/).
3. Create the required resource group and virtual network.
4. Deploy the Windows Server virtual machine.
5. Configure the Network Security Group specifically for the isolated lab.

> **Security note:** Do not expose a honeypot to the public internet without understanding the associated risks. Use an isolated lab environment and restrict management access wherever possible.

### 2. Validate Windows Security Events

After generating controlled failed logon attempts, use Windows Event Viewer to validate Event ID **4625**.

The event provides useful investigation fields including:

- TimeGenerated
- Account
- IpAddress
- Computer
- LogonType
- EventID

### 3. Log Analytics and Microsoft Sentinel

1. Create a Log Analytics Workspace.
2. Create a Microsoft Sentinel instance and connect it to the workspace.
3. Configure the **Windows Security Events via AMA** connector.
4. Create/configure the Data Collection Rule.
5. Confirm that Windows Security Events are arriving in Log Analytics.
6. Validate the telemetry in Microsoft Sentinel.

### 4. GeoIP Enrichment

A Sentinel Watchlist named `geoip` was used to associate source IP addresses with network/geographic information.

**Watchlist configuration:**

- **Name / Alias:** `geoip`
- **Source type:** Local File
- **Header rows:** 0
- **Search Key:** `network`

---

## Detection Scenario

### Primary Detection — Windows Event ID 4625

Event ID **4625** represents a failed logon attempt and was used as the primary signal for this investigation.

### Basic Detection Query

```kql
SecurityEvent
| where EventId == 4625
| order by TimeGenerated desc
```

### Top Source IPs

```kql
SecurityEvent
| where EventId == 4625
| summarize FailedAttempts = count() by IpAddress
| order by FailedAttempts desc
```

### Source IP Investigation

```kql
SecurityEvent
| where IpAddress == "<ATTACKER_IP>"
| where EventId == 4625
| project TimeGenerated, Account, IpAddress, Computer, LogonType
| order by TimeGenerated desc
```

---

## GeoIP Enrichment

The Sentinel Watchlist was used to enrich source IP addresses with geographic/network context.

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

### Investigation Value

The enrichment workflow allows an analyst to move from:

**Raw IP → Network Context → Geographic Context → Investigation**

Geographic information should be treated as contextual intelligence and not as proof of an attacker's physical location.

---

## Detection Engineering

The following query can form the basis of a Microsoft Sentinel Analytics Rule for repeated failed authentication attempts:

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

### Geographic Attack Map Query

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| where isnotempty(IpAddress)
| extend geo = geo_info_from_ip_address(IpAddress)
| extend
    latitude = toreal(geo.latitude),
    longitude = toreal(geo.longitude),
    cityname = tostring(geo.city),
    countryname = tostring(geo.country)
| where isnotempty(latitude) and isnotempty(longitude)
| summarize
    FailureCount = count(),
    TargetAccounts = dcount(TargetAccount)
    by IpAddress, cityname, countryname, latitude, longitude
| extend MapLabel = strcat(
    cityname,
    ", ",
    countryname,
    " — ",
    FailureCount,
    " failed logons (",
    TargetAccounts,
    " targets)"
)
| project
    latitude,
    longitude,
    MapLabel,
    FailureCount,
    TargetAccounts,
    IpAddress,
    cityname,
    countryname
| order by FailureCount desc
```

---

## Investigation Workflow

The investigation followed a typical SOC workflow:

```text
Telemetry
   │
   ▼
Event ID 4625
   │
   ▼
Identify Source IPs
   │
   ▼
Count Failed Attempts
   │
   ▼
Investigate Highest-Volume IPs
   │
   ▼
GeoIP / Watchlist Enrichment
   │
   ▼
Identify Attack Pattern
   │
   ▼
Document Findings
```

---

# Project Evidence Screenshots

The screenshots below provide visual evidence of the Azure infrastructure, telemetry collection, KQL investigation, IP analysis, GeoIP enrichment and attack-map visualisation completed during the lab.

## Azure Infrastructure

### Azure Virtual Network

<img width="1916" height="982" alt="Azure Virtual Network created" src="https://github.com/user-attachments/assets/6ca9b7dd-01ac-4085-8f5a-612b377cdd2e" />

### Azure Virtual Machine

<img width="1992" height="968" alt="Azure Virtual Machine" src="https://github.com/user-attachments/assets/63abbf95-6318-4479-a118-19e2d5cf88f2" />

### Log Analytics Workspace

<img width="1738" height="973" alt="Log Analytics Workspace" src="https://github.com/user-attachments/assets/125a0fc0-d4f5-4f93-83ef-5d3fa6081633" />

### Microsoft Sentinel

<img width="1910" height="986" alt="Microsoft Sentinel Sign-in Logs" src="https://github.com/user-attachments/assets/1928ffe1-30fc-4c70-ab89-495a6fc90a64" />

---

## KQL Investigation

### KQL Investigation

<img width="1999" height="981" alt="KQL Investigation" src="https://github.com/user-attachments/assets/5184ee2b-c7a9-4853-aef2-737d221c5f77" />

### Attacker IP

<img width="1999" height="981" alt="Attacker IP investigation" src="https://github.com/user-attachments/assets/bb138135-69c2-4cf5-ab7a-5c0661ecd636" />

### Attacker Failed Attempts

<img width="1910" height="1023" alt="Attacker failed attempts" src="https://github.com/user-attachments/assets/2026daae-02d9-42c1-8ba9-64274f39c4b3" />

### Sign-in Logs in Microsoft Sentinel

<img width="1910" height="986" alt="Sign-in Logs in Microsoft Sentinel" src="https://github.com/user-attachments/assets/1928ffe1-30fc-4c70-ab89-495a6fc90a64" />

---

## GeoIP Enrichment

### GeoIP Enrichment

<img width="1999" height="1104" alt="GeoIP enrichment" src="https://github.com/user-attachments/assets/c6fe7855-4c82-43fa-8fb5-aaec6fc7cfd4" />

---

## Microsoft Defender for Endpoint

### Advanced Hunting

<img width="2003" height="1125" alt="Microsoft Defender for Endpoint Advanced Hunting" src="https://github.com/user-attachments/assets/7eaf7fb4-f419-453f-8715-98ef8ecae15a" />

### Advanced Hunting Investigation

<img width="1999" height="1104" alt="Advanced Hunting investigation" src="https://github.com/user-attachments/assets/f8d3904e-1d7f-46b8-9646-73573372a1c9" />

---

## Failed Logon Attack Map

### Event ID 4625 Attack Map

<img width="1999" height="1006" alt="Failed Logon Attack Map - Event ID 4625" src="https://github.com/user-attachments/assets/7c682131-5234-435d-8e41-048afe5c4d70" />

### Map Visualisation Settings

- **Visualisation:** Map
- **Latitude Field:** `latitude`
- **Longitude Field:** `longitude`
- **Size Settings:** `FailureCount` — Aggregation: Sum
- **Label Settings:** `MapLabel`
- **Item Colour Settings:** Heatmap using a green-red palette based on `FailureCount`

---

## Key Findings

- **Total failed authentication events:** 1,000 — all associated with Event ID 4625.
- **Most active source IP:** `91.135.255.108` — 236 attempts within approximately 12 minutes (15:31:01–15:43:32 UTC on 2026-08-14).
- **Second-highest source:** `101.6.52.190` — 14 attempts.
- **Other source IPs:** 435 additional IPs generated the remaining activity, with most producing relatively small numbers of attempts.
- **Observed attack window:** 2026-08-14, 15:31:01–17:11:19 UTC.
- **Primary investigation signal:** Windows Event ID 4625.
- **GeoIP context:** 436 unique source IPs were observed.
- **Investigation assessment:** The observed pattern was assessed in the project as primarily consistent with repeated brute-force activity, with some characteristics that may also warrant password-spraying analysis.

> **Note:** GeoIP information and authentication telemetry provide investigative context. They should be correlated with additional evidence before attributing activity to a specific actor or physical location.

---

## SOC Analyst Skills Demonstrated

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

## Repository Structure

```text
homelab-soc-siem-microsoft-sentinel/
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

## Security & Cost Disclaimer

This project is intended for educational and defensive security research.

- Keep the honeypot isolated from production systems.
- Do not store sensitive data, personal credentials, secrets, production workloads or confidential information on the honeypot.
- Restrict administrative access wherever possible.
- Azure resources can generate charges. Stop/deallocate or remove resources when the lab is not in use.
- Treat all observed IP addresses and geographic information as investigative data requiring appropriate context and validation.

---

## Contact

If you have questions about this project or would like to discuss vulnerability management, Microsoft Sentinel, KQL or cybersecurity more broadly:

- 🔗 **GitHub:** [@oluwaseunadenuga](https://github.com/oluwaseunadenuga)
- 💼 **LinkedIn:** [linkedin.com/in/oluwaseunadenuga](https://linkedin.com/in/oluwaseunadenuga)
- 📧 **Email:** Available via LinkedIn

---

<div align="center">

**Homelab SOC SIEM — Microsoft Sentinel & Microsoft Defender**

</div>
