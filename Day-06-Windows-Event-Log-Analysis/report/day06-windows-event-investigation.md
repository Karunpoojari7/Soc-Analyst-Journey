# Day 6: Windows Event Log Investigation

## 1. Objective
Analyze a synthetic Windows Security event dataset using Linux
command-line tools. Identify authentication patterns and events
that warrant further investigation.

## 2. Scope
- Dataset: windows-security-sample.log
- Data type: Synthetic training records
- Environment: Kali Linux
- Tools: grep, sort, uniq, wc, sha256sum
- No real Windows systems or accounts were investigated.

## 3. Event Summary

| Event ID | Meaning | Count |
|---|---|---:|
| 4624 | Successful logon | 3 |
| 4625 | Failed logon | 5 |
| 4720 | User account created | 1 |
| 1102 | Security audit log cleared | 1 |

Total records: 10

## 4. Findings

### Finding 1: Repeated failures followed by success
Three failed logons for alex occurred from 198.51.100.23 between
09:14:02Z and 09:14:15Z. A successful Type 10 logon from the same
address was recorded at 09:15:01Z.

Assessment: Suspicious pattern requiring validation. The records alone
do not prove password guessing or account compromise.

### Finding 2: Repeated failures for guest
Two failed Type 3 logons for guest from 203.0.113.77 occurred at
09:21:05Z and 09:21:12Z.

Assessment: Review the source context and determine whether these
attempts were expected.

### Finding 3: Account creation
Event 4720 records creation of temp_support at 09:18:45Z.
The sample attributes the action to unknown_actor.

Assessment: Verify the account creator and whether the new account
was authorized.

### Finding 4: Security audit log cleared
Event 1102 records a Security audit-log-clearing action attributed
to admin at 09:25:00Z.

Assessment: Determine who performed the action, why it occurred,
and whether it was authorized.

### Additional observation
A successful Type 2 logon for alex was recorded at 09:19:10Z.
Correlate it with other activity if more evidence becomes available.

## 5. Limitations
This is a simplified synthetic dataset, not a genuine Windows EVTX
export. The records do not include all native Windows event fields.
The documentation-only IP addresses and sample account names are
illustrative. No real incident or compromise can be established
from this exercise.

## 6. Recommended Follow-up
1. Validate whether the logons were authorized.
2. Review account-creation details and approved change records.
3. Investigate the audit-log-clearing event and its context.
4. Correlate relevant endpoint, identity and network evidence.
5. Record any additional evidence and update the assessment.

## 7. Conclusion
The sample contains authentication patterns and administrative
events that warrant investigation. Further evidence is required
before classifying any activity as a confirmed security incident.
