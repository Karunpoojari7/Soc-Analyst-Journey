# Network Ports Reference for SOC Investigation

| Port | Protocol | Common service | Investigation context |
|---|---|---|---|
| 53 | TCP/UDP | DNS | Domain resolution |
| 80 | TCP | HTTP | Web traffic |
| 123 | UDP | NTP | Time synchronization |
| 135 | TCP | Microsoft RPC | Windows RPC services |
| 137 | UDP | NetBIOS Name Service | Legacy name resolution |
| 138 | UDP | NetBIOS Datagram | Legacy network services |
| 139 | TCP | NetBIOS Session | Legacy file and printer sharing |
| 443 | TCP | HTTPS | Encrypted web traffic |
| 445 | TCP | SMB | Windows file sharing |
| 500 | UDP | IKE | IPsec key exchange |
| 1433 | TCP | Microsoft SQL Server | Database service |
| 1900 | UDP | SSDP | Device discovery |
| 3306 | TCP | MySQL | Database service |
| 33060 | TCP | MySQL X Protocol | MySQL communication |
| 5432 | TCP | PostgreSQL | Database service |
| 5353 | UDP | mDNS | Multicast DNS |
| 5355 | UDP | LLMNR | Local name resolution |
| 7680 | TCP | Delivery Optimization | Windows content delivery |

## Important investigation principles

- A port number alone does not identify malicious activity.
- Confirm the owning process and executable path.
- Inspect whether an endpoint is listening, established or closed.
- Distinguish loopback, local-network and external connections.
- Check the applicable firewall profile and rules.
- Validate exposure using authorized network testing.

A listening socket does not automatically mean that a service is reachable externally.
