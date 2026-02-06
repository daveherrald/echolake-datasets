# Zscaler CryptoMiner Downloaded Threat Blocked

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Rod Soto, Splunk

## Description

The following analytic identifies attempts to download cryptomining software that are blocked by Zscaler. It leverages web proxy logs to detect blocked actions associated with cryptominer threats, analyzing key data points such as device owner, user, URL category, destination URL, and IP. This activity is significant for a SOC as it helps in early identification and mitigation of cryptomining activities, which can compromise network integrity and resource availability. If confirmed malicious, this activity could lead to unauthorized use of network resources for cryptomining, potentially degrading system performance and increasing operational costs.

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

*Source: [Splunk Security Content](detections/web/zscaler_cryptominer_downloaded_threat_blocked.yml)*
