# Windows IIS Components New Module Added

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the addition of new IIS modules on a Windows IIS server. It leverages the Windows Event log - Microsoft-IIS-Configuration/Operational, specifically EventCode 29, to identify this activity. This behavior is significant because IIS modules are rarely added to production servers, and unauthorized modules could indicate malicious activity. If confirmed malicious, an attacker could use these modules to execute arbitrary code, escalate privileges, or maintain persistence within the environment, potentially compromising the server and sensitive data.

## MITRE ATT&CK

- T1505.004

## Analytic Stories

- IIS Components
- GhostRedirector IIS Module and Rungan Backdoor

## Data Sources

- Windows IIS 29

## Sample Data

- **Source:** IIS:Configuration:Operational
  **Sourcetype:** IIS:Configuration:Operational
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.004/IIS-Configuration-Operational.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_iis_components_new_module_added.yml)*
