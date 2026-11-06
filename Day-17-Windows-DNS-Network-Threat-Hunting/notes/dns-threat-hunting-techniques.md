# DNS and Network Threat-Hunting Techniques

## Establish a baseline
Record configured DNS servers, expected applications, common domains, ordinary protocols and services for the endpoint's role.

## DNS hunting ideas
Review rare domains, long/high-entropy subdomains, query bursts, repeated failures, unusual TXT queries, many domains queried by one process, and DNS requests from unexpected executables. No single characteristic proves maliciousness.

## Correlation
Use ProcessGuid where available. Compare timestamps, query results, destination IPs, ports and process image. Account for CDNs, shared hosting, DNS caching, multiple returned addresses and incomplete time windows.

## Process provenance
For an executable of interest, review full path, Authenticode status/signer, SHA256, file metadata, process creation, parent process, command line and expected application context. A valid signature is useful evidence, not a guarantee of safe behaviour.

## Lab observations
- LLMNR UDP/5355, mDNS UDP/5353 and NetBIOS name service UDP/137 were observed.
- `agy.exe` had a valid Google LLC signature and Antigravity IDE parent.
- `opushutil.exe` had a valid Microsoft signature and Task Scheduler service-host parent.
- These observations did not establish compromise.

## MITRE ATT&CK context
DNS may be relevant to T1071.004 (Application Layer Protocol: DNS) when evidence supports adversarial use. Ordinary DNS activity alone is not a confirmed technique.

## Investigation discipline
Separate observation (what telemetry records), interpretation (what it may mean), conclusion (what is established), and follow-up (what evidence is still needed).
