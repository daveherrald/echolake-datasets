# BITS Job Persistence

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of `bitsadmin.exe` to schedule a BITS job for persistence on an endpoint. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on specific command-line parameters such as `create`, `addfile`, and `resume`. This activity is significant because BITS jobs can be used by attackers to maintain persistence, download malicious payloads, or exfiltrate data. If confirmed malicious, this could allow an attacker to persist in the environment, execute arbitrary code, or transfer sensitive information, necessitating further investigation and potential remediation.

## MITRE ATT&CK

- T1197

## Analytic Stories

- BITS Jobs
- Living Off The Land

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1197/atomic_red_team/windows-sysmon.log

- **Source:** crowdstrike
  **Sourcetype:** crowdstrike:events:sensor
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1197/atomic_red_team/crowdstrike_falcon.log


---

*Source: [Splunk Security Content](detections/endpoint/bits_job_persistence.yml)*
