# Zscaler Legal Liability Threat Blocked

**Type:** Anomaly

**Author:** Rod Soto, Gowthamaraj Rajendran, Splunk

## Description

The following analytic identifies significant legal liability threats blocked by the Zscaler web proxy. It uses web proxy logs to track destinations, device owners, users, URL categories, and actions associated with legal liability. By leveraging statistics on unique fields, it ensures a precise focus on these threats. This activity is significant for SOC as it helps enforce legal compliance and risk management. If confirmed malicious, it could indicate attempts to access legally sensitive or restricted content, potentially leading to legal repercussions and compliance violations.

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

*Source: [Splunk Security Content](detections/web/zscaler_legal_liability_threat_blocked.yml)*
