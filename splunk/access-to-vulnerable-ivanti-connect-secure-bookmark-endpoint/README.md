# Access to Vulnerable Ivanti Connect Secure Bookmark Endpoint

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies access to the /api/v1/configuration/users/user-roles/user-role/rest-userrole1/web/web-bookmarks/bookmark endpoint, which is associated with CVE-2023-46805 and CVE-2024-21887 vulnerabilities. It detects this activity by monitoring for GET requests that receive a 403 Forbidden response with an empty body. This behavior is significant as it indicates potential exploitation attempts against Ivanti Connect Secure systems. If confirmed malicious, attackers could exploit these vulnerabilities to gain unauthorized access or control over the affected systems, leading to potential data breaches or system compromise.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/ivanti/ivanti_bookmark_web_access.log


---

*Source: [Splunk Security Content](detections/web/access_to_vulnerable_ivanti_connect_secure_bookmark_endpoint.yml)*
