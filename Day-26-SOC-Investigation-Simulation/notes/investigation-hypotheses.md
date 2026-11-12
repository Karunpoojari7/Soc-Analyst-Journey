# Day 26 – Investigation Hypothesis Analysis

## Incident
- Incident ID: SOC-2026-026
- Host: nexora-linux-01
- Account: svc-backup
- Source IP: 198.51.100.23
- Dataset: Synthetic training evidence

## Hypothesis 1 – Password Guessing

Supporting observations:
- Five failed SSH authentication events.
- Three usernames targeted.
- Successful password login followed.

Assessment:
Consistent with possible password guessing.

Missing evidence:
- Independent authentication records.
- Account owner validation.
- Authentication policy and expected login baseline.

## Hypothesis 2 – Unauthorised Account Access

Supporting observations:
- Successful login after repeated failures.
- Session opened for svc-backup.

Assessment:
Requires investigation.

Missing evidence:
- User confirmation.
- Session identifier.
- Device and login context.
- Authentication source validation.

## Hypothesis 3 – Privileged Activity

Supporting observations:
- Privileged command event recorded.

Assessment:
Potentially sensitive activity.

Missing evidence:
- Exact sudo command.
- Command exit status.
- Effective user identity.
- Authorisation confirmation.

## Hypothesis 4 – Suspicious Process Execution

Supporting observations:
- Python process execution event.

Assessment:
Insufficient evidence to classify execution as malicious.

Missing evidence:
- Full command line.
- Executable path and hash.
- Parent process.
- Process identifier.

## Hypothesis 5 – Possible Data Transfer

Supporting observations:
- Outbound TLS connection to 203.0.113.77:443.
- Connection associated with a Python process in the dataset.

Assessment:
Destination purpose and traffic contents are unknown.

Missing evidence:
- Network flow records.
- Destination reputation.
- Bytes transferred.
- DNS resolution history.
- TLS metadata.

## Hypothesis 6 – Account Modification

Supporting observations:
- usermod account activity event.

Assessment:
Potential account configuration change.

Missing evidence:
- Exact account modification.
- Before-and-after account state.
- Command execution result.
- Authorisation record.

## Overall Assessment

Classification: UNDER_INVESTIGATION
Priority: HIGH_PRIORITY_REVIEW
Confirmed compromise: NO

All observations are from synthetic training evidence.

Further endpoint, authentication, identity and network
telemetry is required before confirming compromise or
attributing the activity to a particular actor.
