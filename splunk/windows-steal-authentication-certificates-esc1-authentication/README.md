# Windows Steal Authentication Certificates - ESC1 Authentication

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic detects when a suspicious certificate with a Subject Alternative Name (SAN) is issued using Active Directory Certificate Services (AD CS) and then immediately used for authentication. This detection leverages Windows Security Event Logs, specifically EventCode 4887, to identify the issuance and subsequent use of the certificate. This activity is significant because improperly configured certificate templates can be exploited for privilege escalation and environment compromise. If confirmed malicious, an attacker could gain unauthorized access, escalate privileges, and potentially compromise the entire environment.

## MITRE ATT&CK

- T1649
- T1550

## Analytic Stories

- Windows Certificate Services
- Compromised Windows Host

## Data Sources

- Windows Event Log Security 4887
- Windows Event Log Security 4768

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1649/certify_abuse/certify_esc1_abuse_winsecurity.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_steal_authentication_certificates___esc1_authentication.yml)*
