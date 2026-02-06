# Zscaler Scam Destinations Threat Blocked

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Rod Soto, Splunk

## Description

The following analytic identifies blocked scam-related activities detected by Zscaler within a network. It leverages web proxy logs to examine actions flagged as scam threats, focusing on data points such as device owner, user, URL category, destination URL, and IP. This detection is significant for SOC as it helps in the early identification and mitigation of scam activities, ensuring network safety. If confirmed malicious, this activity could indicate attempts to deceive users, potentially leading to data theft or financial loss.

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

*Source: [Splunk Security Content](detections/web/zscaler_scam_destinations_threat_blocked.yml)*
