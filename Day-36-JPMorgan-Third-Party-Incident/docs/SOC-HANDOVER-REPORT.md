# Day 36 — SOC Incident Handover Report

## 1. Case information

Case ID: DAY36-TP-INCIDENT-001
Case name: Simulated Third-Party Vendor Security Incident
Investigation type: SOC investigation and detection engineering
Environment: Synthetic training environment
Status: Investigation documented; validation results must be confirmed

## 2. Executive summary

The investigation examined a simulated third-party vendor environment
containing suspicious authentication, privilege modification,
customer-data export, network transfer, and endpoint process events.

Correlation of these event sources identified multiple indicators
requiring investigation and potential containment.

This case study is an educational simulation. It is not a forensic
reconstruction of the actual JPMorgan incident.

## 3. Key findings

### Identity findings
- Two failed authentication attempts preceded a successful login.
- An MFA challenge was recorded as passed.
- A privilege-grant event was recorded.

### Customer-data findings
- Two export events exceeded the configured 1,000-record threshold.
- The recorded export sizes were 1,200 and 3,500 records.

### Network findings
- Two outbound connections exceeded the configured 1 MB threshold.
- Their combined recorded transfer volume was 20.5 MB.

### Endpoint findings
- PowerShell, archive-tool, and unknown process events were flagged.
- These events require contextual investigation.

## 4. Evidence sources

| Evidence source | File |
|---|---|
| Vendor access | evidence/vendor-logs/vendor-access.csv |
| Customer-data access | evidence/vendor-logs/customer-data-access.csv |
| Identity events | evidence/identity-logs/identity-events.csv |
| Network events | evidence/network-logs/network-events.csv |
| Endpoint events | evidence/endpoint-logs/endpoint-events.csv |

Evidence integrity information is recorded in:
output/evidence-sha256.txt

## 5. Detection results

The detection engine is designed to identify:
- Repeated authentication failures followed by success
- Unexpected privilege grants
- Large customer-data exports
- Large outbound network transfers
- Endpoint processes requiring review

The expected synthetic dataset result is nine alerts.
The benign test dataset is expected to produce zero alerts.

These are expected results, not a claim that the tests passed.
Record the actual test output before marking validation complete.

## 6. Potential impact

The synthetic evidence represents possible unauthorized access
to vendor accounts and customer data.

The actual scope of data exposure, successful transfer, and
business impact cannot be established from this training dataset.

## 7. Recommended actions

1. Validate suspicious vendor-account activity.
2. Review MFA and session information.
3. Confirm whether privilege changes were authorized.
4. Identify the customer records involved in exports.
5. Investigate the destination and context of large transfers.
6. Review endpoint process execution and parent processes.
7. Preserve logs and evidence hashes.
8. Coordinate with the vendor's incident-response team.
9. Review vendor access permissions and data-export controls.

## 8. Outstanding questions

- Were the authentication events authorized?
- Was the privilege change approved?
- Which customer records were accessed?
- Were exported records transmitted outside the environment?
- Were the endpoint processes legitimate?
- Is there evidence of persistence or additional compromised accounts?

## 9. Limitations

- All lab logs are synthetic.
- IP addresses are documentation-only addresses.
- No real JPMorgan internal telemetry was used.
- The actual attack path and attacker identity are not established.
- Large transfers and process names are indicators for investigation,
  not proof of malicious activity.

## 10. Handover

Receiving analyst: SOC / Incident Response Team
Required next action: Validate outstanding questions and determine
whether escalation or containment is warranted.

Handover principle: Preserve evidence, distinguish observations
from hypotheses, and document every investigative decision.
