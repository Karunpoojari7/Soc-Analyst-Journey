# Defender and Windows Firewall Investigation

## 1. Microsoft Defender Posture

### Objective
Assess the endpoint protection configuration and review recent scan activity.

### Observations
- Antivirus service enabled.
- Antivirus protection enabled.
- Real-time protection enabled.
- Behaviour monitoring enabled.
- IOAV protection enabled.
- Network Inspection System enabled.
- Quick Scan activity recorded.
- FullScanAge returned 4294967295, indicating no full scan was recorded in the available status data.

### Event Investigation
Defender Operational events showed multiple Quick Scan attempts.
Some attempts ended with the reason RPC connection rundown, while other scans completed successfully.

### Assessment
Core Defender protection features were enabled during the investigation.
Interrupted scans require follow-up but do not independently establish malware activity or Defender tampering.

## 2. Windows Firewall Investigation

### Objective
Review firewall profiles, application rules, TCP listeners and UDP endpoints.

### Observations
- Domain firewall profile enabled.
- Private firewall profile enabled.
- Public firewall profile enabled.
- Firewall allowed and blocked traffic logging disabled.
- Multiple application-specific inbound rules applied to the Public profile.
- Development applications including Python, Apache, MySQL, Node.js, Docker Desktop, Spring Boot and ADB were present in selected rule records.
- The active network profile was Public.
- The inspected TCP listener snapshot did not show the reviewed development applications listening.
- Windows UDP endpoints included services associated with network discovery and name resolution.

### Assessment
Firewall protection was enabled across all profiles.
Broad Public-profile inbound rules require review.

A firewall allow rule does not prove that an application is listening or remotely reachable. A bound UDP endpoint does not prove external reachability.

Disabled firewall logging represents a visibility limitation.

## 3. Recommendations

1. Review unnecessary Public-profile inbound application rules.
2. Restrict inbound access to required applications and remote addresses.
3. Consider enabling firewall logging with appropriate retention.
4. Investigate interrupted Defender scans.
5. Maintain current Defender protection and signature updates.

## Investigation Limitations
This was a point-in-time configuration review. It did not establish external reachability or prove the absence of malware.
