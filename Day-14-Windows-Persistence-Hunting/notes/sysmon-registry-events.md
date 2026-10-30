# Sysmon Registry Event Reference

## Event ID 12 – Registry Object Created or Deleted

Monitors registry key creation and deletion.

## Event ID 13 – Registry Value Set

Records registry value modifications.

Useful fields:
- TargetObject
- Details
- Image
- ProcessId
- ProcessGuid
- User

## Event ID 14 – Registry Object Renamed

Records registry key or value rename activity.

## Investigation Approach

1. Identify the affected registry path.
2. Identify the responsible process.
3. Review process metadata.
4. Correlate timestamps with related events.
5. Assess whether the activity is expected or suspicious.

## Important Limitation

Sysmon records events according to its active configuration. Absence of an event does not prove that no registry modification occurred.
