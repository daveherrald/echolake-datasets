# Windows AppX Deployment Unsigned Package Installation

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects attempts to install unsigned MSIX/AppX packages using the -AllowUnsigned parameter. This detection leverages Windows event logs from the AppXDeployment-Server, specifically focusing on EventID 603 which indicates the start of a deployment operation with specific deployment flags. The flag value 8388608 corresponds to the -AllowUnsigned option in PowerShell's Add-AppxPackage cmdlet. This activity is significant as adversaries have been observed leveraging unsigned MSIX packages to deliver malware, bypassing signature verification that would normally protect users from malicious packages. If confirmed malicious, this could allow attackers to execute arbitrary code, establish persistence, or deliver malware while evading traditional detection mechanisms.

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

*Source: [Splunk Security Content](detections/endpoint/windows_appx_deployment_unsigned_package_installation.yml)*
