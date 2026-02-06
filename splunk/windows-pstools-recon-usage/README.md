# Windows PsTools Recon Usage

**Type:** Anomaly

**Author:** Nasreddine Bencherchali

## Description

The following analytic identifies execution of Sysinternals PsTools and Sysinternals Suit binaries that are commonly used for reconnaissance and information gathering on
Windows endpoints.
PsTools (PsExec, PsFile, PsGetSid, PsInfo, PsPing, etc.) or Sysinternals Suit tools, are frequently used by administrators for legitimate maintenance but are also leveraged by threat actors to collect system, account, network and service information during discovery and lateral movement.
This detection focuses on process execution and PE metadata telemetry (OriginalFileName).
If confirmed malicious, this activity can indicate targeted reconnaissance and foothold escalation, enabling subsequent lateral movement or credential abuse.


## MITRE ATT&CK

- T1082
- T1046
- T1018

## Analytic Stories

- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://github.com/Splunk/attack_data/raw/master/datasets/attack_techniques/T1082/sysinternals_pstools/sysinternals_pstools.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_pstools_recon_usage.yml)*
