# Ivanti Connect Secure SSRF in SAML Component

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying POST requests targeting endpoints vulnerable to the SSRF issue (CVE-2024-21893) in Ivanti's products. It leverages the Web data model, focusing on endpoints such as /dana-ws/saml20.ws, /dana-ws/saml.ws, /dana-ws/samlecp.ws, and /dana-na/auth/saml-logout.cgi. The detection filters for POST requests that received an HTTP 200 OK response, indicating successful execution. This activity is significant as it may indicate an attempt to exploit SSRF vulnerabilities, potentially allowing attackers to access internal services or sensitive data. If confirmed malicious, this could lead to unauthorized access and data exfiltration.

## MITRE ATT&CK

- T1190

## Analytic Stories

- Ivanti Connect Secure VPN Vulnerabilities

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/ivanti/suricata_ivanti_saml.log


---

*Source: [Splunk Security Content](detections/web/ivanti_connect_secure_ssrf_in_saml_component.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
