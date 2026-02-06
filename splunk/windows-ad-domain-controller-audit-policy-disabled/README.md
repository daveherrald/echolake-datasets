# Windows AD Domain Controller Audit Policy Disabled

**Type:** TTP

**Author:** Dean Luxton

## Description

The following analytic detects the disabling of audit policies on a domain controller. It leverages EventCode 4719 from Windows Security Event Logs to identify changes where success or failure auditing is removed. This activity is significant as it suggests an attacker may have gained access to the domain controller and is attempting to evade detection by tampering with audit policies. If confirmed malicious, this could lead to severe consequences, including data theft, privilege escalation, and full network compromise. Immediate investigation is required to determine the source and intent of the change.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Windows Audit Policy Tampering

## Data Sources

- Windows Event Log Security 4719

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/disable_gpo/windows-security-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_domain_controller_audit_policy_disabled.yml)*
