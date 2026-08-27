# SOC Incident Investigation Report

## 1. Incident Summary

Repeated failed authentication attempts were detected against the Windows honeypot.

## 2. Detection

- Detection platform: Microsoft Sentinel
- Event ID: 4625
- Detection type: Failed authentication
- Source: Windows Security Events

## 3. Timeline

| Time | Activity |
|---|---|
| [TIME] | First failed authentication |
| [TIME] | Multiple failures observed |
| [TIME] | Source IP identified |
| [TIME] | GeoIP enrichment performed |
| [TIME] | Investigation completed |

## 4. Indicators

| Indicator | Value |
|---|---|
| Source IP | [REDACTED] |
| Target account | [VALUE] |
| Event ID | 4625 |
| Failed attempts | [VALUE] |
| First seen | [VALUE] |
| Last seen | [VALUE] |
| GeoIP context | [VALUE] |

## 5. Analysis

The investigation identified repeated failed authentication attempts associated with the source IP above. KQL was used to aggregate the activity, identify targeted accounts and establish the attack timeline.

GeoIP enrichment was used to provide additional context about the source network.

## 6. Assessment

[Document whether the observed behaviour is consistent with brute force, password spraying, automated scanning or another pattern.]

## 7. Recommended Response

- Continue monitoring the source.
- Investigate successful authentication events.
- Review targeted accounts.
- Correlate with additional telemetry.
- Block or contain malicious infrastructure where appropriate.
- Escalate according to the organisation's incident response process.

## 8. Conclusion

The investigation demonstrated the ability to detect, triage, investigate and enrich suspicious authentication activity using Microsoft Sentinel and KQL.
