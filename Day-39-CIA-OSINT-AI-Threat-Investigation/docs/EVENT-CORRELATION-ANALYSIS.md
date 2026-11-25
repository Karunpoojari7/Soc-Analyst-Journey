# Day 39 – Event Correlation Analysis

## Investigation objective

Correlate synthetic identity, API, cloud, endpoint and network
events into a chronological security investigation timeline.

## Evidence sources

- Identity authentication events
- API request events
- Cloud audit events
- Endpoint process events
- Network connection events

## Key observations

1. Repeated authentication failures were followed by a successful login.
2. A privilege modification was recorded.
3. Multiple API requests and an export request followed.
4. Cloud storage access and export activity were recorded.
5. A large outbound network transfer was observed.
6. Endpoint process activity included Python launching curl.

## Correlation hypothesis

The identity, API, cloud and network events sharing the
synthetic source IP 198.51.100.20 may represent a related
sequence of suspicious activity.

## Evidence limitations

- Synthetic records are not actual CIA or ODNI telemetry.
- The endpoint events do not contain source IP information.
- The network records do not identify the originating process.
- The exact content of the exported data is unknown.
- No actual data exfiltration has been established.
- No attacker identity or attribution has been established.

## Conclusion

The dataset contains multiple suspicious indicators that
justify further investigation in a simulated SOC environment.

Temporal and source-IP correlation alone does not prove
that all events belong to one intrusion.
