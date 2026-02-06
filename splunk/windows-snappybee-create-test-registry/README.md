# Windows SnappyBee Create Test Registry

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the Windows registry under `SOFTWARE\Microsoft\Test`, a location rarely used by legitimate applications in a production environment. Monitoring this key is crucial, as adversaries may create or alter values here for monitoring update of itself file path, updated configuration file, or system mark compromised. The detection leverages **Sysmon Event ID 13** (Registry Value Set) to identify unauthorized changes. Analysts should investigate processes associated with these modifications, particularly unsigned executables or suspicious command-line activity, as they may indicate malware or unauthorized software behavior.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Salt Typhoon
- China-Nexus Threat Activity
- SnappyBee

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/test_registry/test_reg.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_snappybee_create_test_registry.yml)*
