# O365 Email Password and Payroll Compromise Behavior

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic identifies when an O365 email recipient receives and then deletes emails for the combination of both password and banking/payroll changes within a short period. This behavior may indicate a compromised account where the threat actor is attempting to redirect the victims payroll to an attacker controlled bank account.

## MITRE ATT&CK

- T1070.008
- T1485
- T1114.001

## Analytic Stories

- Office 365 Account Takeover
- Office 365 Collection Techniques
- Suspicious Emails
- Data Destruction

## Data Sources

- Office 365 Universal Audit Log
- Office 365 Reporting Message Trace

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114/o365_suspect_email_actions/o365_exchange_suspect_events.log

- **Source:** o365_messagetrace
  **Sourcetype:** o365:reporting:messagetrace
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114/o365_suspect_email_actions/o365_messagetrace_suspect_events.log


---

*Source: [Splunk Security Content](detections/cloud/o365_email_password_and_payroll_compromise_behavior.yml)*
