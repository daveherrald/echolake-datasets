# Zscaler Adware Activities Threat Blocked

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

The following analytic identifies potential adware activity blocked by Zscaler. It leverages web proxy logs to detect blocked actions associated with adware threats. Key data points such as device owner, user, URL category, destination URL, and IP are analyzed. This activity is significant as adware can degrade system performance, lead to unwanted advertisements, and potentially expose users to further malicious content. If confirmed malicious, it could indicate an attempt to compromise user systems, necessitating further investigation and remediation to prevent potential data breaches or system exploitation.

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

*Source: [Splunk Security Content](detections/web/zscaler_adware_activities_threat_blocked.yml)*
