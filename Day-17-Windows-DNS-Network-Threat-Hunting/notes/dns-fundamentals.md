# DNS Fundamentals for SOC Analysts

DNS translates names such as `example.com` into resource records used by clients to locate services. DNS commonly uses UDP/TCP port 53; encrypted DNS transports also exist.

## Common record types
| Record | Purpose |
|---|---|
| A | IPv4 address |
| AAAA | IPv6 address |
| CNAME | Alias to another DNS name |
| MX | Mail exchange host |
| NS | Authoritative name server |
| TXT | Text data, often verification or email policy |
| PTR | Reverse lookup |
| SOA | Zone authority and timing information |
| SRV | Service location |

## Investigation fields
Capture timestamp/timezone, query name/type, query status, returned records, process/PID/image/user/ProcessGuid, frequency and surrounding activity.

## Useful commands
```powershell
Resolve-DnsName example.com -Type A
Resolve-DnsName example.com -Type AAAA
Get-DnsClientCache
Get-DnsClientServerAddress
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 22
    StartTime = (Get-Date).AddHours(-1)
} -MaxEvents 20
```

In this lab, `QueryStatus: 0` represented successful results. Status `1460` (timeout) and `9003` (observed on unsuccessful reverse lookups) were also seen. A single failure is not a malicious verdict.

## Potential abuse patterns
DNS tunnelling, DGAs, spoofing/poisoning, DNS-based command and control, and fast-flux behaviour. Treat these as hypotheses; establish baselines and corroborate with multiple sources.
