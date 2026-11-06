# Kerberos Attack Investigation

## AS-REP Roasting
Accounts that do not require Kerberos pre-authentication may expose
authentication material that can be subjected to offline password guessing.
Event 4768 with pre-authentication type 0 is an investigation indicator.

## Kerberoasting
Targets service accounts associated with SPNs. Service-ticket requests,
encryption types and account context should be investigated.

## Tools examined
- impacket-GetNPUsers
- impacket-GetUserSPNs
- impacket-GetADUsers

## Simulated findings
- One AS-REP indicator.
- Three RC4 service-ticket indicators.
- One multiple-service request pattern.

These findings came from simulated data and do not establish an attack.
