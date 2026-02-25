# Windows Developer-Signed MSIX Package Installation

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This detection identifies the installation of developer-signed MSIX packages that lack Microsoft Store signatures. All malicious MSIX packages observed in recent threat campaigns (including those from FIN7, Zloader/Storm-0569, and FakeBat/Storm-1113) were developer-signed rather than Microsoft Store signed. Microsoft Store apps have specific publisher IDs containing '8wekyb3d8bbwe' or 'cw5n1h2txyewy', while developer-signed packages lack these identifiers. This detection focuses on EventID 855 from the Microsoft-Windows-AppXDeployment-Server/Operational logs, which indicates a completed package installation.

## MITRE ATT&CK

- T1553.005
- T1204.002

## Analytic Stories

- MSIX Package Abuse

## Data Sources

- Windows Event Log AppXDeployment-Server 855

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-AppXDeploymentServer/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204.002/appx/windows_appxdeploymentserver.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_developer_signed_msix_package_installation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
