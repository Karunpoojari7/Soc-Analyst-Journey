# Day 7: SIEM Fundamentals and Event Correlation

## Objective
Build a beginner-level authentication-event detection rule using
synthetic logs and Python.

## Scope
- Environment: Kali Linux
- Data: Synthetic authentication events
- Log source: logs/auth-events.log
- Detection script: rules/detect_auth_pattern.py
- Rule definition: rules/failed-logins-followed-by-success.txt

## Detection Logic
Identify at least three failed login events for the same username
and source IP, followed by a successful login within five minutes
of the first failure.

## Findings
- Total authentication events: 10
- Failed login events: 7
- Successful login events: 3
- Users with failed login events: alex, sam, guest
- Detection alert: alex
- Failed login count associated with alert: 3
- Source IP: 192.0.2.25
- Successful login timestamp: 2026-10-23T09:01:02Z

## Interpretation
The synthetic events show repeated failed logins for alex followed
by a successful login. This pattern may warrant investigation in a
real environment, but it does not by itself prove malicious activity
or account compromise.

## Limitations
This is a simplified educational detector. It uses a local text file
rather than a production SIEM and does not provide complete event
normalization, alert deduplication, asset context, or production-grade
correlation across all possible event sequences.

The sample data and IP addresses are for documentation and training.
No real account or incident is represented.

## Conclusion
This lab demonstrated basic log counting, event correlation, a
Python-based detection rule, and initial alert interpretation.
