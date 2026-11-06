# Kerberos Authentication

## Authentication flow
1. AS-REQ: Client requests a Ticket Granting Ticket.
2. Pre-authentication: Client proves knowledge of credentials.
3. AS-REP: Domain Controller responds with the TGT.
4. TGS-REQ: Client requests a service ticket.
5. TGS-REP: Domain Controller returns the service ticket.
6. Client presents the ticket to the service.

## Protocol structures inspected
AS_REQ, AS_REP, TGS_REQ, TGS_REP, KRB_ERROR, PA_DATA.

## Encryption types examined
AES128, AES256 and RC4-HMAC.

## Windows event references
- 4768: TGT requested.
- 4769: Service ticket requested.
- 4771: Kerberos pre-authentication failed.

Impacket protocol structures were inspected locally.
No live Domain Controller authentication was performed.
