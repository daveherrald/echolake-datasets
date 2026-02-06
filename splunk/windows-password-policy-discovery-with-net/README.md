# Windows Password Policy Discovery with Net

**Type:** Hunting

**Author:** Teoderick Contreras, Mauricio Velazco, Nasreddine Bencherchali, Splunk

## Description

The following analytic identifies the execution of `net.exe` with command line arguments aimed at obtaining the computer or domain password policy. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as it indicates potential reconnaissance efforts by adversaries to gather information about Active Directory password policies. If confirmed malicious, this behavior could allow attackers to understand password complexity requirements, aiding in brute-force or password-guessing attacks, ultimately compromising user accounts and gaining unauthorized access to the network.

## MITRE ATT&CK

- T1201

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1201/pwd_policy_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_password_policy_discovery_with_net.yml)*
