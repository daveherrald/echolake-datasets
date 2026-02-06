# Dump LSASS via procdump

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of procdump.exe to dump the LSASS
process, specifically looking for the -mm and -ma command-line arguments. It leverages
data from Endpoint Detection and Response (EDR) agents, focusing on process names,
command-line executions, and parent processes. This activity is significant because
dumping LSASS can expose sensitive credentials, posing a severe security risk. If
confirmed malicious, an attacker could obtain credentials, escalate privileges,
and move laterally within the network, leading to potential data breaches and further
compromise of the environment.


## MITRE ATT&CK

- T1003.001

## Analytic Stories

- CISA AA22-257A
- HAFNIUM Group
- Compromised Windows Host
- Credential Dumping
- Seashell Blizzard
- Storm-2460 CLFS Zero Day Exploitation

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log

- **Source:** crowdstrike
  **Sourcetype:** crowdstrike:events:sensor
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/crowdstrike_falcon.log


---

*Source: [Splunk Security Content](detections/endpoint/dump_lsass_via_procdump.yml)*
