# Day 27 – Threat Hunting Hypotheses

## H1 – Unusual Processes

Objective:
Identify processes that require contextual review.

Telemetry:
PID, PPID, user and process name.

Limitations:
Process names alone cannot establish malicious activity.

## H2 – Unexpected Network Services

Objective:
Review listening ports and active connections.

Telemetry:
Network protocol, socket state and endpoint metadata.

Limitations:
Address and process ownership information may be incomplete.

## H3 – Authentication Anomalies

Objective:
Identify suspicious authentication activity.

Telemetry:
System journal and available SSH records.

Limitations:
Historical log availability depends on retention and configuration.

## H4 – Persistence Mechanisms

Objective:
Review scheduled tasks, cron entries and systemd timers.

Telemetry:
File metadata and timer inventory.

Limitations:
A scheduled task does not automatically indicate malicious persistence.

## H5 – Behavioral Correlation

Objective:
Correlate endpoint and network observations.

Limitations:
Without process-level and session-level attribution,
correlation cannot establish causation.
