# GitHub Enterprise Pause Audit Log Event Stream

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects when a user pauses audit log event streaming in GitHub Enterprise. The detection monitors GitHub Enterprise audit logs for configuration changes that temporarily suspend the audit log streaming functionality, which is used to send audit events to security monitoring platforms. This behavior could indicate an attacker attempting to prevent their malicious activities from being logged and detected by temporarily disabling the audit trail. For a SOC, identifying the pausing of audit logging is critical as it may be a precursor to other attacks where adversaries want to operate undetected during the pause window. The impact could be severe as organizations temporarily lose visibility into user actions, configuration changes, and security events within their GitHub Enterprise environment, potentially allowing attackers to perform malicious activities without detection during the pause period. This creates a temporary blind spot in security monitoring and incident response capabilities.

## MITRE ATT&CK

- T1562.008
- T1195

## Analytic Stories

- GitHub Malicious Activity
- NPM Supply Chain Compromise

## Data Sources

- GitHub Enterprise Audit Logs

## Sample Data

- **Source:** http:github
  **Sourcetype:** httpevent
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/github_audit_log_stream_modified/github.json


---

*Source: [Splunk Security Content](detections/cloud/github_enterprise_pause_audit_log_event_stream.yml)*
