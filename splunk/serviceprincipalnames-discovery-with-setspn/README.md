# ServicePrincipalNames Discovery with SetSPN

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of `setspn.exe` to query the domain for Service Principal Names (SPNs). This detection leverages Endpoint Detection and Response (EDR) data, focusing on specific command-line arguments associated with `setspn.exe`. Monitoring this activity is crucial as it often precedes Kerberoasting or Silver Ticket attacks, which can lead to credential theft. If confirmed malicious, an attacker could use the gathered SPNs to escalate privileges or persist within the environment, posing a significant security risk.

## MITRE ATT&CK

- T1558.003

## Analytic Stories

- Active Directory Discovery
- Active Directory Privilege Escalation
- Compromised Windows Host
- Active Directory Kerberos Attacks

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.003/atomic_red_team/windows-sysmon_setspn.log


---

*Source: [Splunk Security Content](detections/endpoint/serviceprincipalnames_discovery_with_setspn.yml)*
