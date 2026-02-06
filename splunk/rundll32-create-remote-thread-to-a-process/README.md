# Rundll32 Create Remote Thread To A Process

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the creation of a remote thread by rundll32.exe into another process. It leverages Sysmon EventCode 8 logs, specifically monitoring SourceImage and TargetImage fields. This activity is significant as it is a common technique used by malware, such as IcedID, to execute malicious code within legitimate processes, aiding in defense evasion and data theft. If confirmed malicious, this behavior could allow an attacker to execute arbitrary code, escalate privileges, and exfiltrate sensitive information from the compromised host.

## MITRE ATT&CK

- T1055

## Analytic Stories

- IcedID
- Living Off The Land

## Data Sources

- Sysmon EventID 8

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/inf_icedid/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/rundll32_create_remote_thread_to_a_process.yml)*
