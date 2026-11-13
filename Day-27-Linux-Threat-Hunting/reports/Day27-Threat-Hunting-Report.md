# Day 27 – Linux Threat Hunting Report

## 1. Executive Summary

A proactive threat-hunting investigation was conducted
on an authorised Kali Linux endpoint.

The investigation examined process activity, network
connections, authentication telemetry, running services
and scheduled execution mechanisms.

## 2. Investigation Objectives

- Establish endpoint baseline.
- Identify unusual process behaviour.
- Investigate listening ports and connections.
- Review authentication telemetry.
- Examine scheduled tasks and systemd timers.
- Document potential detection opportunities.

## 3. Evidence Sources

- Linux process inventory.
- Linux network socket inventory.
- Systemd service inventory.
- Authentication journal metadata.
- Cron directory metadata.
- Systemd timer inventory.

## 4. Investigation Tools

- Kali Linux
- Python
- ps
- ss
- systemctl
- journalctl
- Bash
- Git

## 5. Automated Investigation

Python scripts were developed to collect sanitized endpoint
telemetry and generate structured investigation outputs.

## 6. Detection Opportunities

- Process discovery.
- Network connection discovery.
- Service discovery.
- Account discovery.
- Scheduled task investigation.

## 7. Assessment

The generated outputs represent investigation candidates
and endpoint baseline observations.

No compromise is confirmed by this automation.

Actual findings must be reviewed against the collected
endpoint telemetry before a final security conclusion.

## 8. Evidence Limitations

- Private endpoint information was intentionally redacted.
- Process command lines were not comprehensively collected.
- Socket ownership may not be available.
- Authentication history depends on journal retention.
- File contents of scheduled tasks were not collected.
- No external reputation checks were performed.

## 9. Recommendations

1. Review unexpected process names and ancestry.
2. Validate listening services against approved configuration.
3. Correlate authentication events with endpoint telemetry.
4. Review scheduled task ownership and execution paths.
5. Improve telemetry retention.
6. Create contextual detection rules.
7. Preserve investigation evidence.

## 10. Conclusion

The investigation demonstrates a repeatable Linux threat-hunting
workflow using native system telemetry and Python automation.

Suspicious observations must be validated before classifying
activity as malicious.

This exercise did not establish confirmed compromise.
