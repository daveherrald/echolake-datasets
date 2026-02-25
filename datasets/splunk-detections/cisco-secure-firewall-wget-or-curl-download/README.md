# Cisco Secure Firewall - Wget or Curl Download

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting outbound connections initiated by command-line tools such as curl or wget. It leverages Cisco Secure Firewall Threat Defense logs and identifies allowed connections (action=Allow) where either the EVE_Process or ClientApplication fields indicate use of these utilities. While curl and wget are legitimate tools commonly used for software updates and scripting, adversaries often abuse them to download payloads, retrieve additional tools, or establish staging infrastructure from compromised systems. If confirmed malicious, this behavior may indicate the download phase of an attack chain or a command-and-control utility retrieval.


## MITRE ATT&CK

- T1053.003
- T1059
- T1071.001
- T1105

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics

## Data Sources

- Cisco Secure Firewall Threat Defense Connection Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/connection_event/connection_events.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___wget_or_curl_download.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
