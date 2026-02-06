# Windows IIS Components Module Failed to Load

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic detects when an IIS Module DLL fails to load due to a configuration problem, identified by EventCode 2282. This detection leverages Windows Application event logs to identify repeated failures in loading IIS modules. Such failures can indicate misconfigurations or potential tampering with IIS components. If confirmed malicious, this activity could lead to service disruptions or provide an attacker with opportunities to exploit vulnerabilities within the IIS environment. Immediate investigation is required to determine the legitimacy of the failing module and to mitigate any potential security risks.

## MITRE ATT&CK

- T1505.004

## Analytic Stories

- IIS Components

## Data Sources

- Windows Event Log Application 2282

## Sample Data

- **Source:** XmlWinEventLog:Application
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.004/2282_windows-application.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_iis_components_module_failed_to_load.yml)*
