# Windows MSIX Package Interaction

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This hunting query detects user interactions with MSIX packages by monitoring EventCode 171 in the Microsoft-Windows-AppXPackaging/Operational logs. These events are generated when a user clicks on or attempts to interact with an MSIX package, even if the package is not fully installed. This information can be valuable for security teams to identify what MSIX packages users are attempting to open in their environment, which may help detect malicious MSIX packages before they're fully installed. Monitoring these interactions can provide early warning of potential MSIX package abuse, which has been leveraged by threat actors such as FIN7, Zloader (Storm-0569), and FakeBat (Storm-1113).

## MITRE ATT&CK

- T1204.002

## Analytic Stories

- MSIX Package Abuse

## Data Sources

- Windows Event Log AppXPackaging 171

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-AppxPackaging/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204.002/appx/windows-appxpackaging.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_msix_package_interaction.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
