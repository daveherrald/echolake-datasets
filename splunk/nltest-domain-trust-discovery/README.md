# NLTest Domain Trust Discovery

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies the execution of `nltest.exe` with command-line arguments `/domain_trusts` or `/all_trusts` to query Domain Trust information. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs and command-line arguments. This activity is significant as it indicates potential reconnaissance efforts by adversaries to understand domain trust relationships, which can inform their lateral movement strategies. If confirmed malicious, this activity could enable attackers to map out trusted domains, facilitating further compromise and pivoting within the network.

## MITRE ATT&CK

- T1482

## Analytic Stories

- Active Directory Discovery
- Qakbot
- Domain Trust Discovery
- Medusa Ransomware
- Cleo File Transfer Software
- Rhysida Ransomware
- IcedID
- Ryuk Ransomware
- Storm-0501 Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1482/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/nltest_domain_trust_discovery.yml)*
