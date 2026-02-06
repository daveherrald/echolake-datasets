# Windows Potential AppDomainManager Hijack Artifacts Creation

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the creation of an .exe file along with its corresponding .exe.config and a .dll in the same directory, which is a common pattern indicative of potential AppDomain hijacking or CLR code injection attempts. This behavior may signal that a malicious actor is attempting to load a rogue assembly into a legitimate application's AppDomain, allowing code execution under the context of a trusted process.

## MITRE ATT&CK

- T1574.014

## Analytic Stories

- SesameOp

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.014/appdomain_hijack_artifacts/appdomain_hijack.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_potential_appdomainmanager_hijack_artifacts_creation.yml)*
