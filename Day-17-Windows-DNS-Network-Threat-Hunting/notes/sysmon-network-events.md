# Sysmon Network and DNS Events

## Event ID 3 — Network connection
Useful fields: `UtcTime`, `ProcessGuid`, `ProcessId`, `Image`, `User`, `Protocol`, `Initiated`, `SourceIp`, `SourcePort`, `DestinationIp`, and `DestinationPort`.

## Event ID 22 — DNS query
Useful fields: `UtcTime`, `ProcessGuid`, `ProcessId`, `QueryName`, `QueryStatus`, `QueryResults`, `Image`, and `User`.

## Event ID 1 — Process creation
Provides process and parent ProcessGuid/PID, image, command line, user, integrity level, file metadata and hashes when collected. It can reconstruct lineage after a process exits.

## Correlation workflow
1. Identify the DNS event and record ProcessGuid, time, query, status and returned IPs.
2. Find Event ID 3 records for the same ProcessGuid.
3. Compare timestamps and destination IPs with DNS results.
4. Use Event ID 1 for process ancestry and command context.
5. Treat correlation as supporting evidence, not proof of application intent or payload contents.

## Lab examples
- PowerShell resolved `example.com`; the same ProcessGuid connected to a returned address over TCP/443.
- `git-remote-https.exe` resolved `github.com` to `20.207.73.82` and connected to that address over TCP/443 with the same ProcessGuid.

Broad NetworkConnect and DnsQuery collection can generate substantial event volume. Monitor log growth and retain a known-good configuration for rollback.
