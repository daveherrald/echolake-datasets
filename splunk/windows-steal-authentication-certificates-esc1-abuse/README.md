# Windows Steal Authentication Certificates - ESC1 Abuse

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic detects when a new certificate is requested or granted against Active Directory Certificate Services (AD CS) using a Subject Alternative Name (SAN). It leverages Windows Security Event Codes 4886 and 4887 to identify these actions. This activity is significant because improperly configured certificate templates can be exploited for privilege escalation and environment compromise. If confirmed malicious, an attacker could gain elevated privileges or persist within the environment, potentially leading to unauthorized access to sensitive information and further exploitation.

## MITRE ATT&CK

- T1649

## Analytic Stories

- Windows Certificate Services

## Data Sources

- Windows Event Log Security 4886
- Windows Event Log Security 4887

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1649/certify_abuse/certify_esc1_abuse_winsecurity.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_steal_authentication_certificates___esc1_abuse.yml)*
