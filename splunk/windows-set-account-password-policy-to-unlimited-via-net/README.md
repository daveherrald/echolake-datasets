# Windows Set Account Password Policy To Unlimited Via Net

**Type:** Anomaly

**Author:** Teoderick Contreras, Nasreddine Bencherchali, Splunk

## Description

The following analytic detects the use of net.exe to update user account policies to set passwords as non-expiring. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions involving "/maxpwage:unlimited" or "/maxpwage:49710", which achieve a similar outcome theoretically. This activity is significant as it can indicate an attempt to maintain persistence, escalate privileges, evade defenses, or facilitate lateral movement. If confirmed malicious, this behavior could allow an attacker to maintain long-term access to compromised accounts, potentially leading to further exploitation and unauthorized access to sensitive information.

## MITRE ATT&CK

- T1489

## Analytic Stories

- Ransomware
- BlackByte Ransomware
- Crypto Stealer
- XMRig

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_set_account_password_policy_to_unlimited_via_net.yml)*
