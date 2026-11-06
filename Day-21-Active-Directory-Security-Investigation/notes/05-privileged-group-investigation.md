# Privileged Group Investigation

## Windows Security Event IDs
- 4728: Member added to global security group.
- 4732: Member added to local security group.
- 4756: Member added to universal security group.
- 4729: Member removed from global security group.
- 4733: Member removed from local security group.
- 4757: Member removed from universal security group.

## Simulated findings
Six events analysed:
- Five membership additions.
- One membership removal.
- Three sensitive group additions.

## SOC investigation procedure
1. Identify the actor.
2. Identify the account added or removed.
3. Identify the target group.
4. Establish event time and affected computer.
5. Verify authorization and change approval.
6. Correlate with authentication and account lifecycle events.

A sensitive group addition is not automatically malicious.
