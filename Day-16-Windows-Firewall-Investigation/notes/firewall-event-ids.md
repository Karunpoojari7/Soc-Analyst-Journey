# Windows Firewall and Filtering Platform Event IDs

## Windows Filtering Platform (WFP)

Windows Filtering Platform provides Windows networking components with traffic filtering and connection auditing capabilities.

## Relevant Security Event IDs

| Event ID | Meaning | SOC investigation use |
|---|---|---|
| 5152 | WFP blocked a packet | Investigate packet drops and source/destination details |
| 5156 | WFP permitted a connection | Investigate permitted network connections |
| 5157 | WFP blocked a connection | Investigate blocked connection attempts |
| 5158 | WFP permitted a bind to a local port | Investigate applications binding to local ports |

## Audit policy subcategories

- Filtering Platform Connection
- Filtering Platform Packet Drop

These audit policies determine whether relevant WFP events are generated.

## Investigation limitations

If auditing is disabled, the absence of corresponding Security events is not evidence that no network activity occurred.

Other evidence sources may include:
- Windows Firewall text logs.
- Sysmon network connection events, if configured.
- Endpoint network telemetry.
- Process and service inventories.
- Network monitoring systems.

## Evidence handling

Record:
- Event ID and timestamp.
- Process and application.
- Source and destination addresses.
- Source and destination ports.
- Protocol and event outcome.
- Relevant audit policy configuration.

Do not enable or change audit policy without authorization.
