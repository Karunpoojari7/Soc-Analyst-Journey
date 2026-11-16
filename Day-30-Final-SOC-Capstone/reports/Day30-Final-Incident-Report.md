# Final SOC Investigation Report — Day 30

## 1. Case Information

- Case ID: SOC-2026-030
- Organization: NEXORA Technologies (synthetic)
- Host: nexora-linux-01
- Investigation date: 16 November 2026
- Dataset: Synthetic security events
- Priority: High
- Status: Under investigation

## 2. Executive Summary

A synthetic Linux security event dataset was reviewed for suspicious
authentication and post-authentication activity.

The investigation identified repeated authentication failures for the
svc-backup account, followed by a successful authentication. Privileged
activity, process execution and an outbound network connection were
also observed.

The activity warrants further investigation. The available evidence
does not establish that the account was compromised.

## 3. Key Findings

1. Six authentication failures were recorded.
2. A successful authentication for svc-backup followed those failures.
3. A session event was recorded.
4. A privileged command was observed.
5. A Python process execution event was recorded.
6. An outbound connection to a documentation-range IP on TCP port 443
   was recorded.
7. Separate activity was observed for backup-operator and should not
   be assumed to belong to the svc-backup session.

## 4. Detection Results

- D30-DET-001: Repeated authentication failures.
- D30-DET-002: Successful login after repeated failures.
- D30-DET-003: Privileged activity requiring validation.
- D30-DET-004: Process execution requiring investigation.
- D30-DET-005: Outbound network connection requiring review.

## 5. Assessment

- Priority: High
- Status: Under investigation
- Compromise confirmed: No
- Recommended escalation: Tier 2

## 6. Evidence Gaps

- No session identifier establishes event-to-session attribution.
- No process parent-child relationship is provided.
- No executable path, hash or command-line telemetry is available
  for the Python process.
- Destination reputation and business purpose are not established.
- No identity owner confirmation or MFA evidence is provided.
- No production host telemetry is included.

## 7. Recommended Next Steps

1. Validate the account owner and expected login activity.
2. Review complete authentication and session records.
3. Obtain EDR process and parent-child telemetry.
4. Review DNS, firewall and network flow records.
5. Check for related activity on other systems.
6. Escalate to Tier 2 for evidence-based scope determination.
7. Apply containment only through the approved incident response plan
   if compromise is substantiated or risk requires urgent action.

## 8. Conclusion

The dataset demonstrates a suspicious sequence of events that requires
further investigation. The evidence is insufficient to confirm account
compromise or establish causation between all observed events.

This report is based entirely on synthetic data and is a training
exercise, not a real-world incident declaration.
