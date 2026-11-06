# SPN Security Investigation

A Service Principal Name identifies a service instance associated
with an account in Active Directory.

Examples:
- HTTP/web01
- MSSQLSvc/db01:1433
- CIFS/fileserver
- LDAP/dc01

## Investigation areas
- SPN-associated accounts.
- Privileged service accounts.
- Passwords configured never to expire.
- Disabled accounts with potentially stale SPNs.
- Service ownership and business justification.

## Simulated findings
Five SPN-associated accounts were identified.
Three accounts had review indicators.

The backup service account had an SPN, privileged membership and a
non-expiring password. A disabled service account retained an SPN.

These are configuration risks, not confirmed compromises.
