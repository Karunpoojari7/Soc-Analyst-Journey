# Day 19 — Windows Endpoint Security Investigation Report

## 1. Executive Summary

A practical endpoint security investigation was conducted on a Windows workstation.

The investigation covered Microsoft Defender, Windows Firewall, running processes, network connections, Windows services, scheduled tasks, registry autoruns, Startup folders and WMI permanent event subscriptions.

No confirmed malicious activity was identified in the collected evidence.

The investigation identified several security visibility and configuration concerns:
- Wazuh agent initialization failure caused by an invalid manager address.
- Firewall traffic logging disabled.
- Broad application-specific inbound rules on the Public firewall profile.
- Some Microsoft Defender Quick Scan attempts interrupted.
- A SoftLanding scheduled-task COM handler whose registered server was not resolved.

These findings require follow-up but do not establish endpoint compromise.

## 2. Scope and Environment

| Item | Description |
|---|---|
| Platform | Windows 11 |
| Shell | Windows PowerShell 5.1 |
| Endpoint protection | Microsoft Defender |
| Endpoint telemetry | Sysmon |
| Network inspection | Windows Firewall and TCP/UDP endpoints |
| Persistence inspection | Services, Task Scheduler, Registry and WMI |
| Method | Read-only endpoint investigation |

## 3. Investigation Findings

### 3.1 Microsoft Defender

Core protection features were enabled, including real-time protection and behaviour monitoring.

Several Quick Scan attempts were interrupted with RPC connection rundown. Other scans completed successfully.

**Assessment:** Defender protection was enabled. Interrupted scans require follow-up, but do not independently indicate malware or tampering.

### 3.2 Windows Firewall

All three firewall profiles were enabled.

Broad application-specific inbound rules were present on the active Public profile. Firewall allowed and blocked traffic logging was disabled.

The inspected TCP listener snapshot did not show the reviewed development applications listening.

**Assessment:** Firewall protection was enabled, but application-rule scope and logging visibility require review.

### 3.3 Processes and Network Activity

Investigated Windows and application processes had plausible explanations based on executable paths, parent processes, service associations and signature verification.

The BITS investigation identified Edge Component Updater metadata, but the transferred artifact was unavailable for independent signature validation.

**Assessment:** No confirmed malicious process or network activity was identified in the investigated evidence.

### 3.4 Service Persistence

The Wazuh agent was configured for automatic startup but remained stopped.

Its logs reported an invalid manager address of 0.0.0.0 and no client configuration.

**Assessment:** Confirmed endpoint monitoring gap. The intended manager deployment must be verified before correcting the configuration.

### 3.5 Scheduled Tasks

Selected Windows and third-party scheduled tasks were investigated.

Two SoftLanding tasks used a COM handler. Its registration and server binary were not resolved.

**Assessment:** The COM handler remains an unresolved investigation item.

### 3.6 Registry and Startup Persistence

Selected Run and RunOnce entries were reviewed.

Six selected third-party executables had valid Authenticode signatures. The Ollama Startup shortcut resolved to an executable with a valid Ollama Inc. signature.

**Assessment:** No confirmed suspicious autorun entry was identified among the entries examined.

### 3.7 WMI Persistence

The SCM Event Log Filter was bound to an NTEventLogEventConsumer named SCM Event Log Consumer.

The configuration was consistent with Windows Service Control Manager event logging.

**Assessment:** No suspicious command-execution or script-execution consumer was identified in the subscription examined.

## 4. Consolidated Findings

| ID | Finding | Disposition |
|---|---|---|
| F-01 | Defender protection features enabled | Positive |
| F-02 | Some Quick Scan attempts interrupted | Follow-up required |
| F-03 | Firewall enabled across all profiles | Positive |
| F-04 | Broad Public-profile inbound rules | Review required |
| F-05 | Firewall traffic logging disabled | Visibility gap |
| F-06 | Investigated process and network activity had plausible explanations | No confirmed malicious activity |
| F-07 | Wazuh agent invalid manager destination | Confirmed monitoring gap |
| F-08 | SoftLanding COM handler not fully resolved | Unresolved |
| F-09 | Selected autorun executables had valid signatures | Positive provenance evidence |
| F-10 | SCM WMI event-log subscription identified | Consistent with event logging |

## 5. MITRE ATT&CK Investigation Mapping

The following techniques informed the investigation. Their presence in this table does not indicate confirmed attacker activity.

| Technique | Investigation relevance |
|---|---|
| T1059.001 | PowerShell execution |
| T1053.005 | Scheduled task persistence |
| T1547.001 | Registry Run Keys and Startup Folder |
| T1546.003 | WMI event subscription |
| T1543.003 | Windows service persistence |

## 6. Recommendations

### High Priority
1. Verify the intended Wazuh manager deployment.
2. Restore Wazuh agent communication after confirming the manager address.
3. Review broad Public-profile inbound application rules.

### Medium Priority
4. Investigate interrupted Defender Quick Scan events.
5. Consider enabling firewall logging with appropriate retention.
6. Resolve the SoftLanding COM handler registration and verify its server binary.

### Ongoing Monitoring
7. Maintain Sysmon telemetry.
8. Monitor unusual PowerShell execution.
9. Review unexpected services, scheduled tasks and autorun changes.
10. Correlate process creation and network activity during future investigations.

## 7. Investigation Limitations

This was a point-in-time investigation of one Windows endpoint.

It did not include:
- Full disk forensic acquisition.
- Memory forensics.
- Enterprise-wide SIEM correlation.
- Threat-intelligence validation of every network destination.
- Complete validation of every installed executable.
- Full resolution of the SoftLanding COM handler.
- Verification of a local Wazuh manager deployment.
- Proof that the endpoint is free of malware.

## 8. Final Assessment

No confirmed malicious activity was identified in the evidence collected.

The endpoint showed positive security indicators, including enabled Defender protection, enabled firewall profiles and valid signatures for selected application executables.

The investigation also identified monitoring and configuration gaps that require remediation or further verification.

**Final disposition:** No confirmed compromise; follow-up investigation and security hardening recommended.

## 9. Evidence Handling

Only sanitized reports, reviewed scripts and approved summary evidence should be published.

Raw event logs, EVTX/ETL files, network captures, usernames, private IP addresses, SIDs, GUIDs, tokens and sensitive command lines must remain private.

A SHA256 manifest should be generated after the portfolio files are finalized.
