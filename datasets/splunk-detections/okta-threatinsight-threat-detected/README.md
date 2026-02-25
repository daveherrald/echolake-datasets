# Okta ThreatInsight Threat Detected

**Type:** Anomaly

**Author:** Michael Haag, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying threats detected by Okta ThreatInsight, such as password spraying, login failures, and high counts of unknown user login attempts. It leverages Okta Identity Management logs, specifically focusing on security.threat.detected events. This activity is significant for a SOC as it highlights potential unauthorized access attempts and credential-based attacks. If confirmed malicious, these activities could lead to unauthorized access, data breaches, and further exploitation of compromised accounts, posing a significant risk to the organization's security posture.

## MITRE ATT&CK

- T1078.004

## Analytic Stories

- Okta Account Takeover

## Data Sources

- Okta

## Sample Data

- **Source:** Okta
  **Sourcetype:** OktaIM2:log
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.004/okta_threatinsight_threat_detected/okta_threatinsight_threat_detected.log


---

*Source: [Splunk Security Content](detections/application/okta_threatinsight_threat_detected.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
