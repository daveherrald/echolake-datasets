# Windows AppX Deployment Full Trust Package Installation

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the installation of MSIX/AppX packages with full trust privileges. This detection leverages Windows event logs from the AppXDeployment-Server, specifically focusing on EventCode 400 which indicates a package deployment operation. Full trust packages are significant as they run with elevated privileges outside the normal AppX container restrictions, allowing them to access system resources that regular AppX packages cannot. Adversaries have been observed leveraging full trust MSIX packages to deliver malware, as documented in recent threat intelligence reports. If confirmed malicious, these packages could allow attackers to execute arbitrary code with elevated privileges, establish persistence, or deliver malware while evading traditional detection mechanisms.

## MITRE ATT&CK

- T1553.005
- T1204.002

## Analytic Stories

- MSIX Package Abuse

## Data Sources

- Windows Event Log AppXDeployment-Server 400

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-AppXDeploymentServer/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204.002/appx/windows_appxdeploymentserver.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_appx_deployment_full_trust_package_installation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
