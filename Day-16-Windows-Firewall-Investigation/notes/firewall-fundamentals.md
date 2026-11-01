# Windows Firewall Fundamentals

## 1. What is Windows Defender Firewall?

Windows Defender Firewall is a host-based security control that filters network traffic entering and leaving a Windows system according to configured rules.

## 2. Firewall Profiles

- Domain: Used when the system is connected to an authenticated domain network.
- Private: Used for trusted private networks.
- Public: Used for untrusted networks such as public Wi-Fi.

## 3. Default Firewall Actions

- Inbound Block: Blocks unsolicited inbound traffic unless an applicable allow rule permits it.
- Outbound Allow: Allows outbound traffic unless an applicable block rule prevents it.

Always inspect the effective policy using the ActiveStore policy store.

## 4. Firewall Rules

An individual rule may specify:
- Direction: Inbound or outbound.
- Action: Allow or block.
- Protocol: TCP, UDP, ICMP or another protocol.
- Local and remote ports.
- Local and remote addresses.
- Application or service.
- Applicable network profiles.

An allow rule represents permission, not proof that traffic occurred.

## 5. Firewall Logging

Windows Firewall can log allowed and dropped packets in pfirewall.log.

Relevant settings:
- LogAllowed
- LogBlocked
- LogFileName
- LogMaxSizeKilobytes

If logging is disabled, the absence of a log file cannot establish that no traffic was permitted or blocked.

## 6. SOC Investigation Approach

1. Establish the active firewall profile and effective policy.
2. Review relevant inbound and outbound rules.
3. Identify listening ports and active connections.
4. Correlate endpoints with owning processes and services.
5. Review available firewall and Windows Security telemetry.
6. Record evidence, limitations and conclusions separately.
