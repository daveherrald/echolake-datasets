# Windows Credentials from Password Stores Creation

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the Windows OS tool cmdkey.exe, which is used to create stored usernames, passwords, or credentials. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs and command-line arguments. This activity is significant because cmdkey.exe is often abused by post-exploitation tools and malware, such as Darkgate, to gain unauthorized access. If confirmed malicious, this behavior could allow attackers to escalate privileges and maintain persistence on the targeted host, facilitating further attacks and potential data breaches.

## MITRE ATT&CK

- T1555

## Analytic Stories

- Compromised Windows Host
- DarkGate Malware
- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1555/cmdkey_create_credential_store/cmdkey_gen_sys.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_credentials_from_password_stores_creation.yml)*
