# Cisco IOS XE Implant Access

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying the potential exploitation of a vulnerability (CVE-2023-20198) in the Web User Interface of Cisco IOS XE software. It detects suspicious account creation and subsequent actions, including the deployment of a non-persistent implant configuration file. The detection leverages the Web datamodel, focusing on specific URL patterns and HTTP methods. This activity is significant as it indicates unauthorized administrative access, which can lead to full control of the device. If confirmed malicious, attackers could maintain privileged access, compromising the device's integrity and security.

## MITRE ATT&CK

- T1190

## Analytic Stories

- Cisco IOS XE Software Web Management User Interface vulnerability

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/cisco/iosxe/ciscocve202320198.log


---

*Source: [Splunk Security Content](detections/web/cisco_ios_xe_implant_access.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
