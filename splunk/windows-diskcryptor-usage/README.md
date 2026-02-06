# Windows DiskCryptor Usage

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of DiskCryptor, identified by the process names "dcrypt.exe" or "dcinst.exe". This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and original file names. DiskCryptor is significant because adversaries use it to manually encrypt disks during an operation, potentially leading to data inaccessibility. If confirmed malicious, this activity could result in complete disk encryption, causing data loss and operational disruption. Immediate investigation is required to mitigate potential ransomware attacks.

## MITRE ATT&CK

- T1486

## Analytic Stories

- Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1486/dcrypt/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_diskcryptor_usage.yml)*
