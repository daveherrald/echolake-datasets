# Ivanti Connect Secure System Information Access via Auth Bypass

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies attempts to exploit the CVE-2023-46805 and CVE-2024-21887 vulnerabilities in Ivanti Connect Secure. It detects GET requests to the /api/v1/totp/user-backup-code/../../system/system-information URI, which leverage an authentication bypass to access system information. The detection uses the Web datamodel to identify requests with a 200 OK response, indicating a successful exploit attempt. This activity is significant as it reveals potential unauthorized access to sensitive system information. If confirmed malicious, attackers could gain critical insights into the system, facilitating further exploitation and compromise.

## MITRE ATT&CK

- T1190

## Analytic Stories

- Ivanti Connect Secure VPN Vulnerabilities
- CISA AA24-241A

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/ivanti/suricata_ivanti_secure_connect_checkphase.log


---

*Source: [Splunk Security Content](detections/web/ivanti_connect_secure_system_information_access_via_auth_bypass.yml)*
