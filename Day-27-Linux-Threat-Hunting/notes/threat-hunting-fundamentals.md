# Day 27 – Linux Threat Hunting

## Objective
Conduct proactive threat hunting on an authorised Linux endpoint.

## Threat Hunting
Threat hunting is the proactive search for suspicious activity
that may not have generated automated security alerts.

## Hunting Approaches
1. Hypothesis-driven hunting
2. IOC-driven hunting
3. Behaviour-driven hunting

## Investigation Areas
1. Process discovery
2. Network connection discovery
3. Authentication investigation
4. Service investigation
5. Scheduled task and persistence investigation

## Important Concepts
- PID: Process identifier.
- PPID: Parent process identifier.
- Socket: Network communication endpoint.
- Persistence: Maintaining execution or access.
- IOC: Indicator of Compromise.
- Baseline: Normal expected system behaviour.

## MITRE ATT&CK References
- T1057: Process Discovery
- T1049: System Network Connections Discovery
- T1007: System Service Discovery
- T1087: Account Discovery
- T1053: Scheduled Task/Job

## Investigation Principles
Unusual activity is not automatically malicious.
Validate findings using multiple sources of evidence.
Document limitations and avoid unsupported conclusions.

## Safety
Only authorised systems are investigated.
No destructive changes or unauthorised access are performed.
