# Windows AD DSRM Account Changes

**Type:** TTP

**Author:** Dean Luxton

## Description

The following analytic identifies changes to the Directory Services Restore Mode (DSRM) account behavior via registry modifications. It detects alterations in the registry path "*\\System\\CurrentControlSet\\Control\\Lsa\\DSRMAdminLogonBehavior" with specific values indicating potential misuse. This activity is significant because the DSRM account, if misconfigured, can be exploited to persist within a domain, similar to a local administrator account. If confirmed malicious, an attacker could gain persistent administrative access to a Domain Controller, leading to potential domain-wide compromise and unauthorized access to sensitive information.

## MITRE ATT&CK

- T1098

## Analytic Stories

- Sneaky Active Directory Persistence Tricks
- Windows Registry Abuse
- Windows Persistence Techniques
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/dsrm_account/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_dsrm_account_changes.yml)*
