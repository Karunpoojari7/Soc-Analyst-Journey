# Day 27 – Detection Use Cases

| ID | Detection opportunity | MITRE ATT&CK |
|---|---|---|
| TH-001 | Unexpected process execution | T1057 |
| TH-002 | Unusual network connections | T1049 |
| TH-003 | Unexpected system services | T1007 |
| TH-004 | Unusual account discovery | T1087 |
| TH-005 | Unexpected scheduled tasks | T1053 |

## Detection Design

Detection candidates require contextual validation.

False positives may arise from legitimate administrative
tools, monitoring software and scheduled maintenance.

The rules are investigation opportunities, not proof of compromise.
