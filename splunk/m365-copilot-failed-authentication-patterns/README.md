# M365 Copilot Failed Authentication Patterns

**Type:** Anomaly

**Author:** Rod Soto

## Description

Detects M365 Copilot users with failed authentication attempts, MFA failures, or multi-location access patterns indicating potential credential attacks or account compromise. The detection aggregates M365 Copilot Graph API authentication events per user, calculating metrics like distinct cities/countries accessed, unique IP addresses and browsers, failed login attempts (status containing "fail" or "error"), and MFA failures (error code 50074). Users are flagged when they access Copilot from multiple cities (cities_count > 1), experience any authentication failures (failed_attempts > 0), or encounter MFA errors (mfa_failures > 0), which are indicators of credential stuffing, brute force attacks, or compromised accounts attempting to bypass multi-factor authentication.

## MITRE ATT&CK

- T1110

## Analytic Stories

- Suspicious Microsoft 365 Copilot Activities

## Data Sources

- M365 Copilot Graph API

## Sample Data

- **Source:** AuditLogs.SignIns
  **Sourcetype:** o365:graph:api
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/m365_copilot/m365_copilot_access.log


---

*Source: [Splunk Security Content](detections/application/m365_copilot_failed_authentication_patterns.yml)*
