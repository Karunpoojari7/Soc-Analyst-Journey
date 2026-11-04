# Day 19 — Windows Endpoint Security Posture and Persistence Investigation

## Objective
Perform a practical, evidence-based investigation of a Windows endpoint, focusing on security posture, process activity, network connections, and persistence mechanisms.

## Investigation Labs
1. Microsoft Defender security posture
2. Windows Firewall configuration
3. Process investigation
4. Process-to-network correlation
5. Windows service persistence hunting
6. Scheduled-task persistence hunting
7. Registry and Startup-folder autoruns
8. WMI permanent event subscriptions

## Tools
- Windows PowerShell 5.1
- Microsoft Defender
- Windows Firewall
- Sysmon
- Windows Event Logs
- CIM/WMI
- Task Scheduler
- Windows Registry

## Key Findings
- Microsoft Defender protection features were enabled.
- Windows Firewall was enabled across all profiles.
- Broad Public-profile inbound rules require review.
- The Wazuh agent could not initialize because of an invalid manager address.
- Selected startup executables had valid digital signatures.
- A Windows Service Control Manager WMI event-logging subscription was identified.
- No confirmed malicious activity was identified in the collected evidence.

## Investigation Approach
Read-only endpoint inspection, telemetry correlation, process provenance verification, persistence analysis, and evidence-based reporting.

## Important Limitations
This was a point-in-time endpoint investigation. No confirmed compromise does not mean the endpoint is proven clean. Some scheduled-task and monitoring issues require follow-up.

## Portfolio Safety
Only sanitized findings and reviewed scripts belong in this repository. Raw event logs, private IP addresses, usernames, SIDs, GUIDs, tokens, and sensitive command lines must not be published.
