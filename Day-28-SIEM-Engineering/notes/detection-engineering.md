# Detection Engineering Notes

## Detection Objectives

- Identify repeated authentication failures.
- Identify successful authentication after repeated failures.
- Correlate post-authentication activity.
- Generate structured alerts.
- Validate detection behaviour using automated tests.

## Detection Rule DET-SSH-001

Five or more failed authentication events from the same
source IP and account within ten minutes.

## Correlation Rule COR-SSH-001

Identify successful authentication following the threshold
of failed authentication events within the defined window.

## Investigation Principles

An alert is an investigation lead, not proof of compromise.

Correlated events do not automatically establish causation.

## Quality Metrics

- True positives
- False positives
- False negatives
- Precision
- Recall
- Detection latency
