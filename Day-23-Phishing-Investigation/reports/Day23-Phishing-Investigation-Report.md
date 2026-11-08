# Day 23 – SOC Phishing Investigation Report

## 1. Executive Summary

A simulated phishing email was investigated using a structured SOC workflow.
The investigation included evidence preservation, email header analysis,
offline URL analysis, attachment triage, and automated phishing detection.

The automated detector identified four investigation indicators and returned
the assessment **REVIEW REQUIRED**.

This is a controlled training exercise using synthetic evidence. It does not
establish that a real phishing incident occurred.

## 2. Investigation Scope

- Investigation type: Phishing email triage
- Evidence type: Synthetic `.eml` email and harmless HTML training file
- Analysis mode: Offline static analysis
- Tools: Python, custom analysis scripts, Linux file utilities
- External URL access: Not performed
- Attachment execution: Not performed
- Mailbox or endpoint telemetry: Not available

## 3. Incident Timeline

| Sequence | Event | Observation |
|---|---|---|
| 1 | Email evidence preserved | Synthetic email saved as an `.eml` file |
| 2 | Header analysis | Sender/reply-to mismatch and reported authentication concerns identified |
| 3 | URL analysis | One HTTPS URL extracted and analysed offline |
| 4 | Attachment triage | Separate harmless HTML training file inspected |
| 5 | Automated detection | Four investigation indicators identified |
| 6 | Evidence validation | JSON outputs validated and original email hash checked |

### Email timestamp

The synthetic email's Date header records:

`Sun, 08 Nov 2026 09:30:00 +0000`

This is the timestamp stated in the sample, not an independently verified delivery time.

## 4. Evidence Register

| Evidence ID | Evidence | SHA-256 |
|---|---|---|
| E-01 | simulated-phishing-email.eml | `69177960d656b54bc406b2a073c03fc34afb95b063b942181b620b0fd3f32255` |
| E-02 | invoice-review.html | `77e9549c6bcaf0a195aa963ca6a256a798694ff7063eb0afb42dd34e94ac06f1` |

### Generated analysis outputs

- `output/header-analysis.json`
- `output/url-analysis.json`
- `output/attachment-analysis.json`
- `output/phishing-investigation.json`

The analysis outputs are derived evidence and should be retained alongside
the original training samples.

## 5. Email Header Findings

| Header / Field | Observed value |
|---|---|
| From | IT Support <security@example.com> |
| Reply-To | account-help@example.net |
| Return-Path | mailer@example.net |
| SPF | fail |
| DKIM | none |
| DMARC | fail |
| Received headers | None present |

### Analyst interpretation

- The From and Reply-To addresses differ.
- The Return-Path also differs from the displayed sender.
- The supplied Authentication-Results reports SPF failure, no DKIM result,
  and DMARC failure.
- No Received headers were available to reconstruct the mail routing path.

These observations warrant further investigation. The supplied authentication
header is part of synthetic evidence and must not be treated as independently
verified gateway telemetry.

## 6. URL Analysis

Extracted URL:

`https://example.net/secure-account-verification`

Observed properties:

- Scheme: HTTPS
- Hostname: example.net
- Path: /secure-account-verification
- Indicator: Account-related keywords

The URL was parsed offline. It was not visited, resolved, or checked against
a live threat-intelligence service.

The example.net domain is used here as a training example. The URL analysis
does not establish malicious hosting or credential theft.

## 7. Attachment Triage

A separate harmless training file was inspected:

- Filename: `invoice-review.html`
- File type: HTML document
- MIME type: text/html
- Size: 319 bytes
- SHA-256: `77e9549c6bcaf0a195aa963ca6a256a798694ff7063eb0afb42dd34e94ac06f1`
- Extension/MIME mismatch: False
- Selected indicator matches: None

Important distinction:

This HTML file was analysed as a standalone attachment-triage exercise.
It was not embedded in the simulated email.

The automated email investigation reported zero embedded attachments.

The inspection was static. No HTML content was executed.

## 8. Automated Detection Results

The automated detector reported:

- Sender/reply-to mismatch: True
- URL count: 1
- Embedded attachment count: 0
- Investigation indicator count: 4
- Assessment: REVIEW REQUIRED

### Indicators identified

1. Account-related keywords
2. Email authentication concern reported
3. From and Reply-To addresses differ
4. Urgency or pressure language

The detector is a triage aid, not a definitive phishing classifier.

## 9. Risk Assessment

**Training assessment: Suspicious characteristics requiring review**

| Area | Assessment |
|---|---|
| Sender identity | Requires review |
| Email authentication | Reported failures require trusted validation |
| URL | Requires reputation and destination verification |
| Attachments | No embedded attachment detected |
| User interaction | Unknown |
| Account compromise | Not established |
| Malware execution | Not established |

No confirmed compromise, credential theft, malware execution, or successful
phishing activity can be concluded from the available evidence.

## 10. Recommended SOC Response

If this were a real organisational investigation, the SOC analyst should:

1. Preserve the original email and relevant mail gateway records.
2. Validate SPF, DKIM, and DMARC results using trusted mail infrastructure.
3. Inspect complete Received headers and Message-ID details.
4. Check the URL using approved, isolated threat-intelligence procedures.
5. Search mail logs for other recipients of the same message.
6. Determine whether users clicked the link or submitted credentials.
7. Correlate available identity, endpoint, DNS, proxy, and authentication logs.
8. If malicious activity is confirmed, follow the organisation's incident
   response process for message removal, account protection, and containment.
9. Document findings and maintain evidence integrity.

These are recommendations, not actions performed during this lab.

## 11. Investigation Limitations

- All email evidence is synthetic.
- Authentication results were not independently validated.
- URL reputation and destination were not checked.
- No live threat-intelligence lookup was performed.
- The standalone HTML file was not part of the email.
- No attachment was executed.
- No mailbox, proxy, DNS, identity, or endpoint telemetry was correlated.
- User interaction and organisational impact are unknown.

## 12. Final Analyst Conclusion

The simulated email contains multiple suspicious characteristics, including
a sender/reply-to mismatch, reported email authentication failures, urgency
language, and an account-related URL.

The automated detector correctly produced the triage assessment
**REVIEW REQUIRED** based on its selected indicators.

The available evidence is insufficient to confirm a real phishing incident.
Further validation using trusted mail gateway, threat-intelligence, identity,
and endpoint telemetry would be required for a definitive incident verdict.

## 13. Skills Demonstrated

- Email evidence preservation and SHA-256 hashing
- Email header parsing
- SPF, DKIM, and DMARC interpretation
- Offline URL analysis
- Static attachment triage
- Python-based phishing detection
- JSON evidence generation and validation
- SOC findings, risk assessment, and incident reporting

---

**Project:** SOC Analyst Learning Journey  
**Training Day:** 23  
**Lab:** Phishing Investigation  
**Environment:** Kali Linux Persistent Live USB  
**Classification:** Synthetic cybersecurity training evidence
