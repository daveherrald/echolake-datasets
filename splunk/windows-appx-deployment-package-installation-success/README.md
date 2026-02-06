# Windows AppX Deployment Package Installation Success

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This analytic detects successful MSIX/AppX package installations on Windows systems by monitoring EventID 854 in the Microsoft-Windows-AppXDeployment-Server/Operational log. This event is generated when an MSIX/AppX package has been successfully installed on a system. While most package installations are legitimate, monitoring these events can help identify unauthorized or suspicious package installations, especially when correlated with other events such as unsigned package installations (EventID 603 with Flags=8388608) or full trust package installations (EventID 400 with HasFullTrust=true).

## MITRE ATT&CK

- T1204.002

## Analytic Stories

- MSIX Package Abuse

## Data Sources

- Windows Event Log AppXDeployment-Server 854

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-AppXDeploymentServer/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204.002/appx/windows_appxdeploymentserver.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_appx_deployment_package_installation_success.yml)*
