# Zscaler Employment Search Web Activity

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Rod Soto, Splunk

## Description

The following analytic identifies web activity related to employment searches within a network. It leverages Zscaler web proxy logs, focusing on entries categorized as 'Job/Employment Search'. Key data points such as device owner, user, URL category, destination URL, and IP are analyzed. This detection is significant for SOCs as it helps monitor potential insider threats by identifying users who may be seeking new employment. If confirmed malicious, this activity could indicate a risk of data exfiltration or other insider threats, potentially leading to sensitive information leakage or other security breaches.

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

*Source: [Splunk Security Content](detections/web/zscaler_employment_search_web_activity.yml)*
