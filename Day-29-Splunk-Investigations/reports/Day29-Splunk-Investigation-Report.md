# Day 29 — Splunk Architecture, SPL and Practical Investigations

## Case Details

- Case ID: SOC-2026-029
- Organization: NEXORA Technologies (fictional)
- Host: nexora-linux-01
- Account: svc-backup
- Priority: High — investigation required
- Dataset: Synthetic JSONL security events
- Splunk execution: Not performed; Splunk is not installed

## 1. Objective

Investigate a synthetic Linux security event sequence, practise event
analysis, understand Splunk architecture and author SPL detection searches.

## 2. Event Summary

| Event Type | Count |
|---|---:|
| AUTH_FAILURE | 6 |
| AUTH_SUCCESS | 1 |
| SESSION | 1 |
| PRIVILEGED_ACTIVITY | 1 |
| PROCESS_EXECUTION | 1 |
| NETWORK_CONNECTION | 1 |
| Total | 11 |

## 3. Investigation Timeline

All timestamps are UTC, 15 November 2026.

| Time | Event | Observation |
|---|---|---|
| 10:00:01–10:05:50 | Authentication failures | Six failures against svc-backup |
| 10:06:20 | Authentication success | Same account and source address |
| 10:07:00 | Session | Session event observed |
| 10:08:10 | Privileged activity | sudo systemctl status ssh |
| 10:09:20 | Process execution | python3, PID 4312 |
| 10:10:30 | Network connection | 203.0.113.80:443 |

## 4. Findings

1. Six failed authentication attempts targeted svc-backup.
2. Successful authentication followed the failures.
3. A session event was recorded.
4. A privileged command was observed.
5. A python3 process execution was observed.
6. An outbound connection to port 443 was recorded.

The source and destination IP addresses are documentation-range
addresses used in this synthetic scenario.

## 5. Assessment

HIGH PRIORITY — escalate for further investigation.

The sequence warrants investigation for possible credential guessing
followed by successful access and subsequent activity.

However, the evidence does not establish malicious intent or compromise.

Compromise confirmed: NO.

## 6. Evidence Gaps

- No original SSH authentication logs.
- No session identifier linking the events.
- No process parent-child relationship.
- No python3 command-line arguments.
- No packet capture or TLS inspection.
- No destination reputation evidence.
- No account owner or maintenance-window confirmation.

## 7. Recommended Actions

1. Validate authentication events against original system logs.
2. Confirm whether svc-backup is authorized for interactive login.
3. Review account privileges and credential history.
4. Examine process execution telemetry and process ancestry.
5. Investigate the destination using approved network telemetry.
6. Preserve relevant original logs.
7. Escalate to Tier 2 for validation and containment decisions if
   unauthorized activity is confirmed.

## 8. Splunk and SPL Work

Ten SPL searches were authored in the queries directory.

Splunk was not installed or executed in this environment.
Therefore these are prepared SPL queries, not verified Splunk search results.

The Python analysis script independently processes the synthetic
JSONL dataset. Python output must not be represented as Splunk output.

## 9. Learning Outcomes

- Reviewed Splunk forwarder, indexer and search-head architecture.
- Practised event fields, event types, time ranges and aggregation.
- Authored SPL queries for authentication and network investigations.
- Built a reproducible Python investigation.
- Used automated tests to validate findings.
- Documented evidence gaps and correlation limitations.

## 10. Conclusion

The synthetic event sequence demonstrates how repeated authentication
failures followed by successful authentication and subsequent activity
can be prioritized for investigation.

The available evidence supports escalation for validation, not a
confirmed compromise finding.
