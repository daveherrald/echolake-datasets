# Zscaler Virus Download threat blocked

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Rod Soto, Splunk

## Description

The following analytic identifies attempts to download viruses that were blocked by Zscaler within a network. It leverages web proxy logs to detect blocked actions indicative of virus download attempts. Key data points such as device owner, user, URL category, destination URL, and IP are analyzed. This activity is significant as it helps in early detection and remediation of potential virus threats, enhancing network security. If confirmed malicious, this activity could indicate an attempt to compromise the network, potentially leading to data breaches or further malware infections.

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

*Source: [Splunk Security Content](detections/web/zscaler_virus_download_threat_blocked.yml)*
