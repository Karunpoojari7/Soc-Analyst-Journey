# Registry, Startup and WMI Persistence Investigation

## 1. Registry Autorun Investigation

### Objective
Identify applications configured to launch automatically through Windows Run and RunOnce registry keys.

### Evidence Sources
- HKLM Run
- HKLM RunOnce
- HKLM WOW6432Node Run
- HKCU Run
- HKCU RunOnce

### Observations
Selected entries were associated with:
- Windows Security
- Realtek Audio
- Microsoft OneDrive
- Apache Tomcat
- Microsoft Teams
- Docker Desktop
- Postman Agent
- Windscribe
- Google Chrome
- Microsoft Edge

Six selected third-party executables were verified and had valid Authenticode signatures from their expected publishers.

### Assessment
No confirmed suspicious registry autorun entry was identified among the entries examined.

A valid signature is useful provenance evidence but does not guarantee that an application is vulnerability-free or harmless.

## 2. Startup Folder Investigation

### Objective
Inspect current-user and common Windows Startup folders.

### Observations
- The current-user Startup folder contained an Ollama shortcut and desktop.ini.
- The common Startup folder contained desktop.ini.
- The Ollama shortcut targeted the installed Ollama desktop application.
- The target executable existed and had a valid signature from Ollama Inc.

### Assessment
The inspected Startup entry was consistent with the installed Ollama application.

No confirmed suspicious Startup-folder entry was identified.

## 3. WMI Permanent Event Subscription Investigation

### Objective
Investigate WMI permanent event subscriptions for potential event-triggered persistence.

### Evidence Sources
- __EventFilter
- __EventConsumer
- __FilterToConsumerBinding

### Observations
One event filter was identified:
- Name: SCM Event Log Filter
- Namespace: root\cimv2
- Query language: WQL
- Query: MSFT_SCMEventLogEvent

One consumer was identified:
- Name: SCM Event Log Consumer
- Class: NTEventLogEventConsumer
- Source: Service Control Manager

The filter-to-consumer binding connected the SCM event filter to the event-log consumer.

### Assessment
The inspected configuration was consistent with a Windows Service Control Manager event-logging subscription.

No suspicious command-execution or script-execution consumer was identified in the subscription examined.

## 4. Investigation Limitations

- Not every autorun executable was independently verified.
- The assessment covered selected registry and Startup locations.
- A valid digital signature does not establish that a file is completely safe.
- The WMI conclusion applies only to the subscription examined.
