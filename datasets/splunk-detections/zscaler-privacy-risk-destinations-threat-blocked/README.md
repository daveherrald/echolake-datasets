# Zscaler Privacy Risk Destinations Threat Blocked

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Rod Soto, Splunk

## Description

This dataset contains sample data for identifying blocked destinations within a network that are deemed privacy risks by Zscaler. It leverages web proxy logs, focusing on entries marked as "Privacy Risk." Key data points such as device owner, user, URL category, destination URL, and IP are analyzed. This activity is significant for a SOC as it helps monitor and manage privacy risks, ensuring a secure network environment. If confirmed malicious, this activity could indicate attempts to access or exfiltrate sensitive information, posing a significant threat to data privacy and security.

## MITRE ATT&CK

- T1566

## Analytic Stories

- Zscaler Browser Proxy Threats

## Data Sources


## Sample Data

- **Source:** zscaler
  **Sourcetype:** zscalernss-web
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566/zscalar_web_proxy/zscalar_web_proxy.json


---

*Source: [Splunk Security Content](detections/web/zscaler_privacy_risk_destinations_threat_blocked.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
