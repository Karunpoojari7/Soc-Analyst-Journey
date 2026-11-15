# Splunk Search Processing Language

| Command | Purpose |
|---|---|
| search | Filter events |
| where | Filter using expressions |
| fields | Select fields |
| table | Display fields |
| stats | Aggregate events |
| timechart | Summarize events over time |
| eval | Create or modify fields |
| sort | Sort results |
| dedup | Remove duplicates |
| rex | Extract fields |
| lookup | Enrich events |

## Performance considerations

- Select an appropriate time range.
- Filter events early.
- Avoid unnecessary high-cardinality aggregations.
- Validate timestamp extraction.
- Treat correlation as an investigative lead, not proof.
