# Rundll32 Shimcache Flush

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of a suspicious rundll32 command line used to clear the shim cache. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs and command-line arguments. This activity is significant because clearing the shim cache is an anti-forensic technique aimed at evading detection and removing forensic artifacts. If confirmed malicious, this action could hinder incident response efforts, allowing an attacker to cover their tracks and maintain persistence on the compromised machine.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Unusual Processes
- Living Off The Land
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/shimcache_flush/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/rundll32_shimcache_flush.yml)*
