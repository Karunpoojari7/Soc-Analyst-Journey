# Incident 001 — Repeated SSH Authentication Failures

**Case ID:** SOC-2026-001  
**Analyst:** SOC Analyst Trainee  
**Date:** 16 October 2026  
**Environment:** Synthetic Training Lab  
**Status:** Awaiting Further Evidence

## 1. Executive Summary

Five failed password-authentication events were identified in a synthetic SSH authentication log. Four events originated from the same recorded source IP address and targeted the username `admin`.

The available evidence suggests a pattern that warrants investigation, but it does not establish malicious intent or confirm a system compromise.

## 2. Evidence Collected

- Total failed password-authentication events: 5
- Source IP `203.0.113.25`: 4 failed attempts
- Source IP `198.51.100.40`: 1 failed attempt
- One successful public-key authentication was recorded for user `analyst` from `192.0.2.10`.
- The successful authentication used a different source IP and account.

## 3. Investigation Performed

1. Filtered the synthetic log for failed password-authentication events.
2. Counted the failed events using Linux command-line tools.
3. Grouped the failed events by recorded source IP address.
4. Reviewed successful authentication events.
5. Constructed a preliminary event timeline.

## 4. Timeline

| Time (UTC) | Event |
|---|---|
| 09:00:01 | Failed login for `admin` |
| 09:00:04 | Failed login for `admin` |
| 09:00:07 | Failed login for `admin` |
| 09:00:10 | Failed login for `admin` |
| 09:01:15 | Successful public-key authentication for `analyst` from a different source |
| 09:02:30 | Failed login for `guest` from another source |

## 5. Initial Assessment

The four repeated failures from the same source may be consistent with password-guessing activity. However, the sample is insufficient to determine whether the activity was malicious.

The successful authentication cannot be linked to the failed attempts using the available evidence.

## 6. Recommended Next Steps

- Review authentication events over a wider time window.
- Check for successful authentication from the same source as the failed attempts.
- Validate the relevant accounts and whether the activity was expected.
- Correlate available endpoint, network, and identity logs.
- Escalate if additional evidence or organizational policy warrants it.

## 7. Limitations

All events in this investigation are synthetic and were created for training. No real attack or compromise has been established.

## 8. Final Disposition

**Pending further evidence.**

This report documents a preliminary investigation and does not represent a confirmed security incident.
