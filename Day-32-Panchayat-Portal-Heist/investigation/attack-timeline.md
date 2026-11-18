# Day 32 - Correlated Incident Timeline

Synthetic defensive SOC investigation.

| Timestamp | Category | Evidence | Event ID | Description |
|---|---|---|---|---|
| 2026-11-18T10:15:00+00:00 | AUTHENTICATION | SUPPORTING | AUTH-010 | bdo_mandapam_01 authentication failure from 198.51.100.25 |
| 2026-11-18T10:16:00+00:00 | AUTHENTICATION | SUPPORTING | AUTH-011 | bdo_mandapam_01 authentication failure from 198.51.100.25 |
| 2026-11-18T10:17:00+00:00 | AUTHENTICATION | SUPPORTING | AUTH-012 | bdo_mandapam_01 authentication failure from 198.51.100.25 |
| 2026-11-18T10:18:00+00:00 | AUTHENTICATION | SUPPORTING | AUTH-013 | bdo_mandapam_01 authentication failure from 198.51.100.25 |
| 2026-11-18T10:19:00+00:00 | MFA | STRONG | MFA-010 | bdo_mandapam_01 MFA_REQUEST from 198.51.100.25 |
| 2026-11-18T10:20:00+00:00 | AUTHENTICATION | STRONG | AUTH-020 | bdo_mandapam_01 authentication success from 198.51.100.25 |
| 2026-11-18T10:20:00+00:00 | MFA | STRONG | MFA-011 | bdo_mandapam_01 MFA_REQUEST from 198.51.100.25 |
| 2026-11-18T10:21:00+00:00 | AUTHENTICATION | SUPPORTING | AUTH-021 | finance_checker_01 authentication success from 198.51.100.25 |
| 2026-11-18T10:21:00+00:00 | MFA | STRONG | MFA-012 | bdo_mandapam_01 MFA_REQUEST from 198.51.100.25 |
| 2026-11-18T10:22:00+00:00 | MFA | STRONG | MFA-013 | bdo_mandapam_01 MFA_REQUEST from 198.51.100.25 |
| 2026-11-18T10:23:00+00:00 | MFA | STRONG | MFA-014 | bdo_mandapam_01 MFA_REQUEST from 198.51.100.25 |
| 2026-11-18T10:24:00+00:00 | MFA | STRONG | MFA-020 | bdo_mandapam_01 MFA_APPROVED from 198.51.100.25 |
| 2026-11-18T10:25:00+00:00 | MFA | SUPPORTING | MFA-021 | finance_checker_01 MFA_APPROVED from 198.51.100.25 |
| 2026-11-18T10:27:00+00:00 | FINANCIAL_TRANSACTION | STRONG | TXN-003 | approved payment of INR 2,500,000 to BEN-SIM-901 |
| 2026-11-18T10:29:00+00:00 | FINANCIAL_TRANSACTION | STRONG | TXN-004 | approved payment of INR 3,000,000 to BEN-SIM-902 |
| 2026-11-18T10:32:00+00:00 | FINANCIAL_TRANSACTION | STRONG | TXN-005 | approved payment of INR 1,800,000 to BEN-SIM-903 |
| 2026-11-18T10:38:00+00:00 | FINANCIAL_TRANSACTION | STRONG | TXN-007 | approved payment of INR 2,200,000 to BEN-SIM-904 |

## Evidence Summary

- Strong timeline events: 11
- Supporting timeline events: 6
- Correlated transactions: 4
- Approved financial exposure: INR 9,500,000
