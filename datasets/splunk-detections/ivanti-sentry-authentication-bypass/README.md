# Ivanti Sentry Authentication Bypass

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying unauthenticated access attempts to the System Manager Portal in Ivanti Sentry, exploiting CVE-2023-38035. It detects this activity by monitoring HTTP requests to specific endpoints ("/mics/services/configservice/*", "/mics/services/*", "/mics/services/MICSLogService*") with a status code of 200. This behavior is significant for a SOC as it indicates potential unauthorized access, which could lead to OS command execution as root. If confirmed malicious, this activity could result in significant system compromise and data breaches, especially if port 8443 is exposed to the internet.

## MITRE ATT&CK

- T1190

## Analytic Stories

- Ivanti Sentry Authentication Bypass CVE-2023-38035

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/ivanti/ivanti_sentry_CVE_2023_38035.log


---

*Source: [Splunk Security Content](detections/web/ivanti_sentry_authentication_bypass.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
