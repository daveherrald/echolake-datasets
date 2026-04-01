# Windows Office Product Spawned Rundll32 With No DLL

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting any Windows Office Product spawning `rundll32.exe` without a `.dll` file extension. This behavior is identified using Endpoint Detection and Response (EDR) telemetry, focusing on process and parent process relationships. This activity is significant as it is a known tactic of the IcedID malware family, which can lead to unauthorized code execution. If confirmed malicious, this could allow attackers to execute arbitrary code, potentially leading to data exfiltration, system compromise, or further malware deployment. Immediate investigation and containment are recommended.

## MITRE ATT&CK

- T1566.001

## Analytic Stories

- Spearphishing Attachments
- CVE-2023-36884 Office and Windows HTML RCE Vulnerability
- Compromised Windows Host
- Prestige Ransomware
- Graceful Wipe Out Attack
- Crypto Stealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon_icedid.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_office_product_spawned_rundll32_with_no_dll.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
