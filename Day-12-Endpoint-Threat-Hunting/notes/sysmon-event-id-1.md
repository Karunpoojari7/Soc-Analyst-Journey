# Sysmon Event ID 1 — Learning Notes

- Event ID 1 records process creation.
- Image identifies the executable path.
- CommandLine records the launch command and arguments.
- ParentImage identifies the recorded parent executable.
- User provides account context.
- Hashes can help identify files.
- ProcessGuid can help correlate process events.

## SOC Analyst Lesson

Process telemetry is evidence of activity, not an automatic verdict.
Investigate command lines, parent-child relationships, user context,
timestamps, and related events before assessing risk.
