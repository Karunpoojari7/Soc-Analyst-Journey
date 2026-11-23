# Day 37 — SOC Investigation Report

## Case
Simulated NCIC-style government database intrusion investigation.

## Evidence
Five synthetic CSV datasets were generated:
- Identity
- API
- Database
- Network
- Endpoint

All IP addresses are documentation-only examples.

## Detection summary
Total alerts: 12

- HIGH | NCIC-001 | Repeated login failures followed by success
- HIGH | NCIC-002 | Privilege change requires authorization review
- HIGH | NCIC-005 | Records export API request
- HIGH | NCIC-003 | Unusually high database read: 2500 records
- CRITICAL | NCIC-005 | Large database export: 3500 records
- MEDIUM | NCIC-004 | Database UPDATE requires authorization review
- MEDIUM | NCIC-004 | Database DELETE requires authorization review
- HIGH | NCIC-006 | Large outbound transfer: 8500000 bytes
- HIGH | NCIC-006 | Large outbound transfer: 12000000 bytes
- MEDIUM | NCIC-007 | Endpoint process review: powershell.exe
- MEDIUM | NCIC-007 | Endpoint process review: archive-tool.exe
- MEDIUM | NCIC-007 | Endpoint process review: unknown.exe

## Assessment
The synthetic evidence contains suspicious authentication activity,
a privilege change, unusual database access, data export activity,
large outbound transfers, and endpoint processes requiring review.

These observations warrant investigation in this simulation. They do
not prove that the real FBI NCIC system experienced these events.

## Recommended response
1. Validate the identity and MFA events.
2. Review authorization for privilege changes.
3. Confirm the business purpose of database queries and exports.
4. Correlate network transfers with approved application activity.
5. Preserve endpoint and database audit evidence.
6. Restrict suspicious sessions only under approved response authority.
7. Document confirmed impact separately from investigative hypotheses.
