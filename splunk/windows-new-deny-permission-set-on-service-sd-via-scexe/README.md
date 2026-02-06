# Windows New Deny Permission Set On Service SD Via Sc.EXE

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Michael Haag, Splunk

## Description

The following analytic detects changes in a service security descriptor where a new deny ace has been added. It leverages data from Endpoint Detection and Response (EDR) agents, specifically searching for any process execution involving the "sc.exe" binary with the "sdset" flag targeting any service and adding a dedicated deny ace. If confirmed malicious, this could allow an attacker to escalate their privileges, blind defenses and more.

## MITRE ATT&CK

- T1564

## Analytic Stories

- Defense Evasion or Unauthorized Access Via SDDL Tampering

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1564/sc_sdset_tampering/sc_sdset_tampering_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_new_deny_permission_set_on_service_sd_via_sc_exe.yml)*
