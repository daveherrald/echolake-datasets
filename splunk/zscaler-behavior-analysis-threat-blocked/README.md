# Zscaler Behavior Analysis Threat Blocked

**Type:** Anomaly

**Author:** Rod Soto, Gowthamaraj Rajendran, Splunk

## Description

The following analytic identifies threats blocked by the Zscaler proxy based on behavior analysis. It leverages web proxy logs to detect entries where actions are blocked and threat names and classes are specified. This detection is significant as it highlights potential malicious activities that were intercepted by Zscaler's behavior analysis, providing early indicators of threats. If confirmed malicious, these blocked threats could indicate attempted breaches or malware infections, helping security teams to understand and mitigate potential risks in their environment.

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

*Source: [Splunk Security Content](detections/web/zscaler_behavior_analysis_threat_blocked.yml)*
