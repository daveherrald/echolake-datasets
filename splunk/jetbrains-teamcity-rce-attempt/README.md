# JetBrains TeamCity RCE Attempt

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects attempts to exploit the CVE-2023-42793 vulnerability in JetBrains TeamCity On-Premises. It identifies suspicious POST requests to /app/rest/users/id:1/tokens/RPC2, leveraging the Web datamodel to monitor specific URL patterns and HTTP methods. This activity is significant as it may indicate an unauthenticated attacker attempting to gain administrative access via Remote Code Execution (RCE). If confirmed malicious, this could allow the attacker to execute arbitrary code, potentially compromising the entire TeamCity environment and leading to further unauthorized access and data breaches.

## MITRE ATT&CK

- T1190

## Analytic Stories

- JetBrains TeamCity Unauthenticated RCE
- CISA AA23-347A
- JetBrains TeamCity Vulnerabilities

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/jetbrains/teamcity.log


---

*Source: [Splunk Security Content](detections/web/jetbrains_teamcity_rce_attempt.yml)*
