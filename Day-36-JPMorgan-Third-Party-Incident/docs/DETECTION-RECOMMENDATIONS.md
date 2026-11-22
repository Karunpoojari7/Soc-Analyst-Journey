# Day 36 — Detection Engineering Recommendations

## 1. Objective

Improve detection of suspicious third-party access and possible
customer-data exposure through correlation of identity, application,
network, and endpoint telemetry.

## 2. Recommended detection use cases

### DET-01 — Repeated authentication failures followed by success

Logic:
- Detect at least two failed authentication attempts.
- Followed by a successful login for the same account.
- Occurring within a configurable time window.

Investigate:
- Source IP and geographic context
- MFA result
- Device and session information
- Account's normal login behaviour

### DET-02 — Unexpected vendor privilege change

Logic:
- Detect privilege or role changes involving vendor accounts.
- Compare the change against approved access requests.

Investigate:
- Actor and target account
- Previous and new privileges
- Change timestamp
- Approval and change-ticket reference

### DET-03 — Unusual customer-data export

Logic:
- Alert when a vendor account exports more records than its
  approved threshold or normal baseline.

Investigate:
- Number and type of records
- Account and application
- Export destination
- Business justification
- Related authentication events

### DET-04 — Large outbound network transfer

Logic:
- Detect outbound transfers above a configured threshold.
- Correlate with recent data-export events where possible.

Investigate:
- Destination and port
- Source endpoint
- Transfer volume
- Session duration
- Related application activity

A large transfer alone is not proof of data exfiltration.

### DET-05 — Suspicious endpoint process activity

Logic:
- Monitor unusual execution of scripting tools, archive utilities,
  and unknown processes on vendor-managed endpoints.

Investigate:
- Process path and hash
- Parent process
- Executing user
- Command-line arguments
- File and network activity

A process name alone is not sufficient to establish malicious activity.

## 3. Correlation strategy

Correlate events using:

- Account identifier
- Source IP address
- Endpoint or device identifier
- Session identifier, when available
- Timestamp
- Application and export identifiers

Normalize timestamps to a common timezone before correlation.

## 4. Alert quality

Each alert should contain:

- Alert ID
- Detection rule ID
- Severity
- Event timestamp
- Account and source
- Evidence references
- Detection reason
- Analyst investigation status

## 5. False-positive management

Before escalating, consider:

- Approved bulk exports
- Scheduled vendor integrations
- Authorized administrative changes
- VPN or proxy address changes
- Software deployment activity
- Backup and archive operations

Tune thresholds using normal activity baselines rather than
assuming every unusual event is malicious.

## 6. Continuous improvement

- Review detection performance regularly.
- Test rules with both suspicious and benign datasets.
- Record false positives and missed detections.
- Maintain version control for detection logic.
- Reassess vendor access and data-export baselines.
