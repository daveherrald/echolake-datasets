# Zscaler Phishing Activity Threat Blocked

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Rod Soto, Splunk

## Description

The following analytic identifies potential phishing attempts blocked by Zscaler within a network. It leverages web proxy logs to detect actions tagged as HTML.Phish. The detection method involves analyzing critical data points such as user, threat name, URL, and hostname. This activity is significant for a SOC as it serves as an early warning system for phishing threats, enabling prompt investigation and mitigation. If confirmed malicious, this activity could indicate an attempt to deceive users into divulging sensitive information, potentially leading to data breaches or credential theft.

## MITRE ATT&CK

- T1566

## Analytic Stories

- Zscaler Browser Proxy Threats
- Hellcat Ransomware

## Data Sources


## Sample Data

- **Source:** zscaler
  **Sourcetype:** zscalernss-web
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566/zscalar_web_proxy/zscalar_web_proxy.json


---

*Source: [Splunk Security Content](detections/web/zscaler_phishing_activity_threat_blocked.yml)*
