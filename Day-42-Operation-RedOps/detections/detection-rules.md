# Day 42 – Operation RedOps Detection Rules

## Rule 1: Possible Password Spraying

Objective:
Identify a source IP generating failed login attempts against multiple accounts.

Logic:
- Group failed authentication events by source IP.
- Count distinct targeted usernames.
- Generate a HIGH severity alert when at least 3 accounts are targeted.

MITRE ATT&CK:
T1110.003 – Password Spraying

Investigation:
Check whether a successful login follows the failures.
Review the targeted accounts and source IP.

## Rule 2: SSH Connection Over Port 443

Objective:
Identify SSH connections using destination port 443.

Logic:
- Identify SSH connection events.
- Check whether destination_port equals 443.
- Generate a MEDIUM severity alert.

Investigation:
Review destination, process, network flow and connection context.

Important:
Port 443 alone does not prove tunnelling or malicious activity.
Both detections require analyst investigation.
