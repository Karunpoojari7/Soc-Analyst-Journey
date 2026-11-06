# Sysmon configuration files

Keep the validated `day17-sysmon-config.xml` and preserved `day14-original-reference.xml` in this directory.

The Day 17 configuration used:
- NetworkConnect with `onmatch="exclude"` and no exclusions.
- DnsQuery with `onmatch="exclude"` and no exclusions.
- RegistryEvent with `onmatch="include"` and the Day 14 persistence TargetObject filters.

Do not overwrite the Day 14 original. Broad Event ID 3 and 22 collection can increase log volume; monitor retention and consider scoped filters for longer-term use.
