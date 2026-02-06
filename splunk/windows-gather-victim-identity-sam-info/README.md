# Windows Gather Victim Identity SAM Info

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects processes loading the samlib.dll or samcli.dll modules, which are often abused to access Security Account Manager (SAM) objects or credentials on domain controllers. This detection leverages Sysmon EventCode 7 to identify these DLLs being loaded outside typical system directories. Monitoring this activity is crucial as it may indicate attempts to gather sensitive identity information. If confirmed malicious, this behavior could allow attackers to obtain credentials, escalate privileges, or further infiltrate the network.

## MITRE ATT&CK

- T1589.001

## Analytic Stories

- Brute Ratel C4

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/brute_ratel/loading_samlib/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_gather_victim_identity_sam_info.yml)*
