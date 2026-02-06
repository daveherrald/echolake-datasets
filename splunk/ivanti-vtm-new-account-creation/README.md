# Ivanti VTM New Account Creation

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This analytic detects potential exploitation of the Ivanti Virtual Traffic Manager (vTM) authentication bypass vulnerability (CVE-2024-7593) to create new administrator accounts. The vulnerability allows unauthenticated remote attackers to bypass authentication on the admin panel and create new admin users. This detection looks for suspicious new account creation events in the Ivanti vTM audit logs that lack expected authentication details, which may indicate exploitation attempts.

## MITRE ATT&CK

- T1190

## Analytic Stories

- Ivanti Virtual Traffic Manager CVE-2024-7593
- Scattered Lapsus$ Hunters
- Hellcat Ransomware

## Data Sources

- Ivanti VTM Audit

## Sample Data

- **Source:** ivanti_vtm
  **Sourcetype:** ivanti_vtm_audit
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/ivanti/ivanti_vtm_audit.log


---

*Source: [Splunk Security Content](detections/application/ivanti_vtm_new_account_creation.yml)*
