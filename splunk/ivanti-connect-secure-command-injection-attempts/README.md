# Ivanti Connect Secure Command Injection Attempts

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies attempts to exploit the CVE-2023-46805 and CVE-2024-21887 vulnerabilities in Ivanti Connect Secure. It detects POST requests to specific URIs that leverage command injection to execute arbitrary commands. The detection uses the Web datamodel to monitor for these requests and checks for a 200 OK response, indicating a successful exploit attempt. This activity is significant as it can lead to unauthorized command execution on the server. If confirmed malicious, attackers could gain control over the system, leading to potential data breaches or further network compromise.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/ivanti/suricata_ivanti_secure_connect_exploitphase.log


---

*Source: [Splunk Security Content](detections/web/ivanti_connect_secure_command_injection_attempts.yml)*
