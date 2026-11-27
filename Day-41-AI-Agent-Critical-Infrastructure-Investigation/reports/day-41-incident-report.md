# Day 41 — Critical Infrastructure Security Investigation

## 1. Case information

- Case ID: DAY41-CASE-001
- Investigation: AI-agent-associated activity hypotheses
- Environment: Fictional electricity utility
- Dataset: Synthetic security telemetry
- Report generated (UTC): 2026-11-27T15:25:59.411203+00:00

## 2. Executive summary

This investigation analyses synthetic authentication, API and firewall
events to identify suspicious activity and correlate evidence across
multiple security data sources.

This is a controlled training scenario, not an investigation of an
actual Swiss victim or production critical infrastructure.

## 3. Dataset overview

| Log source | Events |
|---|---:|
| Authentication | 7 |
| API access | 7 |
| Firewall | 5 |
| **Total** | **19** |

## 4. Source IP distribution

| Source IP | Event count |
|---|---:|
| 198.51.100.77 | 15 |
| 192.0.2.44 | 4 |

## 5. Detection results

- Total generated alerts: 5

| Detection rule | Alert count |
|---|---:|
| DET001 | 1 |
| DET002 | 1 |
| DET003 | 1 |
| DET004 | 2 |

### Severity distribution

| Severity | Alert count |
|---|---:|
| HIGH | 4 |
| MEDIUM | 1 |

## 6. Correlated incidents

Total correlated incident records: 3

| Incident | Source IP | Severity | Rules | Evidence count |
|---|---|---|---|---:|
| INC-DAY41-001 | 192.0.2.44 | HIGH | DET004 | 1 |
| INC-DAY41-002 | 192.0.2.44 | HIGH | DET004 | 3 |
| INC-DAY41-003 | 198.51.100.77 | HIGH | DET001, DET002, DET003, DET004 | 15 |

## 7. Timeline overview

- Timeline events: 19
- Earliest timestamp: 2026-11-27T09:00:00Z
- Latest timestamp: 2026-11-27T09:22:00Z

See `docs/attack-timeline.md` for the event-by-event timeline.

## 8. Investigation assessment

The detection rules identify suspicious patterns in the supplied
synthetic telemetry. Each alert requires analyst review and validation
against account ownership, authorised activity, network architecture
and relevant endpoint or application evidence.

A shared source IP or chronological sequence does not independently
prove that events were performed by the same operator.

## 9. AI-agent attribution limitations

The available logs do not establish whether an AI agent was involved.
Additional evidence would be required, including automation identities,
agent execution audit trails, endpoint process telemetry and identity
provider records.

## 10. Impact assessment

No real operational impact can be inferred from this synthetic dataset.
A connection attempt does not prove successful access to an industrial
control system.

## 11. Recommendations

- Enforce MFA for privileged accounts.
- Monitor repeated authentication failures and unusual login success.
- Restrict administrative API access.
- Apply network segmentation between IT and OT environments.
- Monitor industrial protocol access attempts.
- Preserve endpoint, identity and automation audit logs.
- Validate alerts against authorised maintenance and administrative activity.

## 12. Evidence integrity

SHA-256 manifest: `evidence/sha256-manifest.txt`.
Run `sha256sum -c evidence/sha256-manifest.txt` to verify the listed files.

## 13. Analyst conclusion

This lab demonstrates a synthetic multi-source SOC investigation workflow.
The final conclusions must remain limited to the events and detections
actually present in the generated dataset. AI-agent attribution and
real-world compromise are not established.
