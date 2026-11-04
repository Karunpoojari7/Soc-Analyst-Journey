# Service and Scheduled-Task Persistence Investigation

## 1. Windows Service Investigation

### Objective
Review Windows services for unexpected configurations, startup behaviour and potential persistence mechanisms.

### Evidence Sources
- Win32_Service inventory
- Service startup configuration
- Service executable paths
- Service accounts
- Windows System event logs
- Wazuh agent configuration and logs

### Observations
- Sysmon service was running with automatic startup.
- MySQL and PostgreSQL services were running as expected for the installed development environment.
- Remote Registry and Remote Access services were disabled.
- Wazuh agent was configured for automatic startup but was stopped.
- Wazuh agent logs repeatedly reported an invalid manager address of 0.0.0.0 and no client configuration.

### Assessment
The Wazuh agent configuration contained an invalid manager destination, preventing successful initialization.

This represents a confirmed endpoint monitoring gap. The investigation did not establish that an attacker stopped or modified the service.

The Wazuh manager deployment was not verified, and the agent was not reconfigured during this assessment.

## 2. Scheduled-Task Investigation

### Objective
Identify scheduled tasks that could provide recurring execution or persistence.

### Evidence Sources
- Scheduled-task inventory
- Task execution paths and arguments
- Task principals and run levels
- Last-run timestamps and results
- Exported task XML
- COM handler configuration

### Observations
Selected tasks associated with audio software, K-Lite Codec Pack, Alienware Command Center and Windows Hotpatch monitoring were examined.

Two SoftLanding tasks used a COM handler rather than a conventional executable action.

The COM Class ID was identified, but its registry registration and associated server binary were not resolved.

### Assessment
Several investigated tasks had plausible Windows or installed-software explanations.

The SoftLanding COM handler remains an unresolved investigation item and should not be classified as benign or malicious without resolving its registered component.

## 3. Recommendations

1. Verify the intended Wazuh manager deployment.
2. Correct the agent manager destination only after confirming the manager address.
3. Validate successful agent registration and event delivery.
4. Resolve the SoftLanding COM handler registration.
5. Verify the associated COM server binary and publisher.
6. Continue monitoring unexpected service and scheduled-task changes.

## Investigation Limitations
Not every service or scheduled task was independently validated. The investigation did not establish the complete provenance of the SoftLanding COM handler.
