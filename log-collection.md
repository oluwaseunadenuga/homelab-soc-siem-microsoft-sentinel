# Log Collection

## Objective

Centralise Windows Security Events for investigation through Log Analytics and Microsoft Sentinel.

## Components

- Azure Monitor Agent (AMA)
- Data Collection Rule (DCR)
- Log Analytics Workspace
- Microsoft Sentinel
- Windows Security Events via AMA connector

## Validation

Confirm that Event ID 4625 events from the honeypot are visible in the Log Analytics Workspace.

```kql
SecurityEvent
| where EventId == 4625
| order by TimeGenerated desc
```
