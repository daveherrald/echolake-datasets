# Process Writing DynamicWrapperX

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic detects a process writing the dynwrapx.dll file to disk and registering it in the registry. It leverages data from the Endpoint datamodel, specifically monitoring process and filesystem events. This activity is significant because DynamicWrapperX is an ActiveX component often used in scripts to call Windows API functions, and its presence in non-standard locations is highly suspicious. If confirmed malicious, this could allow an attacker to execute arbitrary code, escalate privileges, or maintain persistence within the environment. Immediate investigation of parallel processes and registry modifications is recommended.

## MITRE ATT&CK

- T1059
- T1559.001

## Analytic Stories

- Remcos

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/process_writing_dynamicwrapperx.yml)*
