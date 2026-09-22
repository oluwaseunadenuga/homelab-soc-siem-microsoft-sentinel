# Homelab SOC SIEM — Microsoft Sentinel & Microsoft Defender

![Azure](https://img.shields.io/badge/Microsoft%20Azure-Cloud%20Security-blue)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-SIEM-purple)
![KQL](https://img.shields.io/badge/KQL-Threat%20Hunting-orange)
![SOC](https://img.shields.io/badge/SOC-Lab-green)
![Status](https://img.shields.io/badge/Status-Completed-success)

<img width="940" height="529" alt="Microsoft Sentinel SOC lab overview" src="https://github.com/user-attachments/assets/ca59d82e-c803-4102-9694-9ea1fcf87e08" />

## Executive Summary

This homelab demonstrates an end-to-end SOC monitoring and investigation workflow built with Microsoft Azure, Microsoft Sentinel, Log Analytics, Azure Monitor Agent (AMA), Data Collection Rules (DCR), KQL, Sentinel Watchlists and Microsoft Defender for Endpoint.

An intentionally exposed Windows honeypot was used in an isolated lab environment to generate failed authentication telemetry. Windows Event ID **4625** was collected centrally, queried with KQL, enriched with GeoIP context and visualised to support investigation of repeated authentication failures.

The project demonstrates practical capabilities across **SIEM monitoring, log collection, detection engineering, threat hunting, IOC analysis, enrichment, investigation and security reporting**.

> **Lab safety:** This is an educational defensive-security lab. The honeypot should be isolated from production systems and must not contain sensitive information, production credentials or confidential data.

---

## Business / SOC Problem

Security teams need to identify suspicious authentication activity from large volumes of security telemetry and quickly determine:

- Which systems are generating suspicious activity?
- Which source IPs are generating the highest number of failures?
- Which accounts are being targeted?
- When did the activity occur?
- Does the activity resemble brute force or password spraying?
- Can the source IPs be enriched with additional context?
- Can the detection logic be converted into a repeatable SIEM analytics rule?

This project demonstrates a practical workflow for answering those questions using Microsoft security tooling.

---

## Objectives

- Deploy an Azure Windows honeypot for telemetry generation.
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
              │       Workspace         │
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
| Microsoft Defender for Endpoint | Endpoint telemetry and Advanced Hunting |
| Sentinel Workbook | Data visualisation |

---

## Lab Implementation

### 1. Azure Infrastructure

1. Create an Azure subscription suitable for the lab.
2. Sign in to the Azure Portal.
3. Create the required resource group and virtual network.
4. Deploy the Windows Server virtual machine.
5. Configure the Network Security Group for the isolated lab.
6. Validate the VM and network configuration.

### 2. Generate and Validate Failed Logons

Controlled failed logon activity was generated against the lab VM.

Windows Event Viewer was then used to validate **Event ID 4625** and confirm that the expected security telemetry was being generated.

Key fields included:

- TimeGenerated
- Account
- IpAddress
- Computer
- LogonType
- EventID

### 3. Centralise Telemetry

1. Create a Log Analytics Workspace.
2. Connect Microsoft Sentinel to the workspace.
3. Configure **Windows Security Events via AMA**.
4. Configure the Data Collection Rule.
5. Confirm that Windows Security Events are being ingested.
6. Validate the data in Log Analytics and Microsoft Sentinel.

### 4. GeoIP Enrichment

A Sentinel Watchlist named `geoip` was used to enrich source IP addresses.

**Configuration:**

- **Name / Alias:** `geoip`
- **Source type:** Local File
- **Header rows:** 0
- **Search Key:** `network`

---

# Detection Engineering

## Primary Detection — Event ID 4625

Windows Event ID **4625** represents a failed logon attempt and was used as the primary investigation signal.

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

## Brute-Force Detection Logic

This query groups failed logons by source IP and identifies sources exceeding a defined threshold.

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

Microsoft Sentinel scheduled analytics rules use KQL queries against a defined lookback period and can generate alerts when the configured threshold is met. citeturn0search1turn0search2

### Recommended Analytics Rule Design

| Setting | Example |
|---|---|
| Rule name | Excessive Windows Failed Logons |
| Data source | SecurityEvent |
| Event | 4625 |
| Grouping | IpAddress |
| Threshold | 10+ failures |
| Lookback | Defined investigation window |
| Severity | Medium — tune to environment |
| Entity mapping | IP address, account, host |
| Tactic | Credential Access |
| Technique | Brute Force |

> The threshold above is a lab example rather than a universal production threshold. Production thresholds should be tuned to the environment's normal authentication baseline.

---

# Threat Investigation

## Investigation Workflow

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
Review Target Accounts
   │
   ▼
GeoIP / Watchlist Enrichment
   │
   ▼
Assess Attack Pattern
   │
   ▼
Document Findings
```

Microsoft Sentinel incidents aggregate relevant evidence from alerts and support investigation through entities, timelines and investigation views. citeturn0search4turn0search7

## Investigation Questions

The investigation focused on:

1. What was the volume of failed authentication?
2. Which source IP generated the most failures?
3. Which accounts were targeted?
4. Was activity concentrated within a short time window?
5. Were multiple accounts targeted from the same IP?
6. Were multiple source IPs involved?
7. What geographic/network context was available?
8. Does the evidence support a brute-force hypothesis, password-spraying hypothesis, or both?
9. What additional telemetry would be required before escalation?

---

# MITRE ATT&CK Mapping

The project can be mapped to the following ATT&CK concepts based on the observed authentication activity:

| ATT&CK Area | Technique | Relevance to Lab |
|---|---|---|
| Credential Access | **T1110 — Brute Force** | Repeated failed authentication attempts |
| Credential Access | **T1110.003 — Password Spraying** | Relevant where one password is attempted against multiple accounts; requires supporting evidence |
| Initial Access | **T1078 — Valid Accounts** | Relevant only if valid credentials are subsequently obtained or abused; not established by failed logons alone |

MITRE ATT&CK documents Brute Force and Password Spraying as credential-access techniques, while Valid Accounts concerns abuse of existing credentials. The latter should therefore not be claimed solely from Event ID 4625 failures. citeturn0search9turn0search11

---

# GeoIP Enrichment

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

GeoIP information is contextual intelligence and should not be treated as proof of an attacker's physical location.

---

# Attack Map

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

### Map Visualisation Settings

- **Visualisation:** Map
- **Latitude Field:** `latitude`
- **Longitude Field:** `longitude`
- **Size:** `FailureCount` — Sum
- **Label:** `MapLabel`
- **Colour:** Heatmap based on `FailureCount`

---

# Project Evidence Screenshots

The screenshots below provide evidence of the Azure deployment, telemetry pipeline, KQL investigation, GeoIP enrichment, Defender Advanced Hunting and attack-map visualisation.

## Azure Infrastructure

### Azure Virtual Network

<img width="1916" height="982" alt="Azure Virtual Network created" src="https://github.com/user-attachments/assets/6ca9b7dd-01ac-4085-8f5a-612b377cdd2e" />

### Azure Virtual Machine

<img width="1992" height="968" alt="Azure Virtual Machine" src="https://github.com/user-attachments/assets/63abbf95-6318-4479-a118-19e2d5cf88f2" />

### Log Analytics Workspace

<img width="1738" height="973" alt="Log Analytics Workspace" src="https://github.com/user-attachments/assets/125a0fc0-d4f5-4f93-83ef-5d3fa6081633" />

### Microsoft Sentinel

<img width="1910" height="986" alt="Microsoft Sentinel Sign-in Logs" src="https://github.com/user-attachments/assets/1928ffe1-30fc-4c70-ab89-495a6fc90a64" />

## KQL Investigation

### KQL Investigation

<img width="1999" height="981" alt="KQL Investigation" src="https://github.com/user-attachments/assets/5184ee2b-c7a9-4853-aef2-737d221c5f77" />

### Attacker IP

<img width="1999" height="981" alt="Attacker IP investigation" src="https://github.com/user-attachments/assets/bb138135-69c2-4cf5-ab7a-5c0661ecd636" />

### Attacker Failed Attempts

<img width="1910" height="1023" alt="Attacker failed attempts" src="https://github.com/user-attachments/assets/2026daae-02d9-42c1-8ba9-64274f39c4b3" />

### Sign-in Logs in Microsoft Sentinel

<img width="1910" height="986" alt="Sign-in Logs in Microsoft Sentinel" src="https://github.com/user-attachments/assets/1928ffe1-30fc-4c70-ab89-495a6fc90a64" />

## GeoIP Enrichment

### GeoIP Enrichment

<img width="1999" height="1104" alt="GeoIP enrichment" src="https://github.com/user-attachments/assets/c6fe7855-4c82-43fa-8fb5-aaec6fc7cfd4" />

## Microsoft Defender for Endpoint

### Advanced Hunting

<img width="2003" height="1125" alt="Microsoft Defender for Endpoint Advanced Hunting" src="https://github.com/user-attachments/assets/7eaf7fb4-f419-453f-8715-98ef8ecae15a" />

### Advanced Hunting Investigation

<img width="1999" height="1104" alt="Advanced Hunting investigation" src="https://github.com/user-attachments/assets/f8d3904e-1d7f-46b8-9646-73573372a1c9" />

## Failed Logon Attack Map

### Event ID 4625 Attack Map

<img width="1999" height="1006" alt="Failed Logon Attack Map - Event ID 4625" src="https://github.com/user-attachments/assets/7c682131-5234-435d-8e41-048afe5c4d70" />

---

# Incident Investigation Summary

## Incident Type

**Repeated Failed Authentication Activity**

## Detection Signal

**Windows Security Event ID 4625**

## Observed Window

**2026-08-14, 15:31:01–17:11:19 UTC**

## Key Source

**91.135.255.108**

## Highest Observed Volume

**236 failed attempts**

## Initial Assessment

The project evidence shows a concentrated burst of failed authentication activity from the highest-volume source IP, alongside a larger population of lower-volume source IPs.

The observed pattern was assessed within the project as primarily consistent with **repeated brute-force activity**, with some characteristics that warrant further investigation for password spraying.

This is an investigation hypothesis rather than attribution of malicious intent to a specific actor.

## Analyst Assessment

The available telemetry supports escalation for further investigation because of:

- High-volume repeated authentication failures.
- A clear source-IP outlier.
- Activity targeting multiple account names.
- Concentrated activity during a defined time period.
- Additional distributed source-IP activity.
- Available GeoIP enrichment for investigation context.

---

# Findings

- **Total failed authentication events:** 1,000.
- **Primary event:** Event ID 4625.
- **Most active source IP:** `91.135.255.108`.
- **Attempts from most active source:** 236.
- **Second-highest source:** `101.6.52.190` with 14 attempts.
- **Unique source IPs:** 436.
- **Observed attack window:** approximately 100 minutes on 2026-08-14.
- **Primary host:** `mulan-window120`.
- **GeoIP enrichment:** available for source-IP investigation.
- **Investigation conclusion:** evidence is consistent with repeated failed-authentication activity requiring further triage and correlation.

---

# Recommended SOC Response Workflow

If this were a production investigation, the next steps would include:

1. Validate whether the source IP is known, expected or trusted.
2. Review the targeted accounts and determine whether any are privileged.
3. Correlate authentication failures with successful logons.
4. Search for successful authentication from the same IP.
5. Review endpoint telemetry around the relevant timestamps.
6. Check for account lockouts or password changes.
7. Review additional authentication sources.
8. Enrich IP indicators using approved threat-intelligence sources.
9. Determine whether the activity meets the organisation's incident threshold.
10. If confirmed malicious, follow the organisation's containment and response procedures.

Microsoft Sentinel analytics rules can generate alerts and incidents from detection logic, while entity mapping improves investigation context and correlation. citeturn0search2turn0search4

---

# What This Project Demonstrates

### SOC Monitoring

- Centralised security telemetry.
- Microsoft Sentinel monitoring.
- Windows authentication-event analysis.

### Detection Engineering

- KQL-based detection logic.
- Threshold-based failed-logon detection.
- Source-IP aggregation.
- Investigation-oriented query design.

### Threat Hunting

- Historical event analysis.
- Source-IP investigation.
- Account targeting analysis.
- Endpoint Advanced Hunting.

### Investigation

- Event ID 4625 analysis.
- Timeline analysis.
- IOC/source-IP analysis.
- GeoIP enrichment.
- Geographic visualisation.

### Security Reporting

- Evidence collection.
- Investigation summary.
- Analyst assessment.
- Recommended response workflow.

---

# Repository Structure

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

# Security & Cost Disclaimer

This project is intended for educational and defensive security research.

- Keep the honeypot isolated from production systems.
- Do not store sensitive data, personal credentials, secrets, production workloads or confidential information on the honeypot.
- Restrict administrative access wherever possible.
- Azure resources can generate charges. Stop/deallocate or remove resources when the lab is not in use.
- Treat observed IP addresses and geographic information as investigative data requiring appropriate context and validation.

---

# Contact

If you have questions about this project or would like to discuss Microsoft Sentinel, KQL, vulnerability management or cybersecurity:

- 🔗 **GitHub:** [@oluwaseunadenuga](https://github.com/oluwaseunadenuga)
- 💼 **LinkedIn:** [linkedin.com/in/oluwaseunadenuga](https://linkedin.com/in/oluwaseunadenuga)
- 📧 **Email:** Available via LinkedIn

---

<div align="center">

**Homelab SOC SIEM — Microsoft Sentinel & Microsoft Defender**

</div>
