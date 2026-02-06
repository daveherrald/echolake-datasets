# Enumerate Users Local Group Using Telegram

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a Telegram process enumerating all network users in a local group. It leverages EventCode 4798, which is generated when a process enumerates a user's security-enabled local groups on a computer or device. This activity is significant as it may indicate an attempt to gather information on user accounts, a common precursor to further malicious actions. If confirmed malicious, this behavior could allow an attacker to map out user accounts, potentially leading to privilege escalation or lateral movement within the network.

## MITRE ATT&CK

- T1087

## Analytic Stories

- XMRig
- Compromised Windows Host
- Water Gamayun

## Data Sources

- Windows Event Log Security 4798

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087/enumerate_users_local_group_using_telegram/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/enumerate_users_local_group_using_telegram.yml)*
