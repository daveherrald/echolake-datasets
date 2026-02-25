# Cisco Secure Firewall - Binary File Type Download

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting file downloads involving executable, archive, or scripting-related file types that are commonly used in malware delivery. 
These file types include formats like PE executables, shell scripts, autorun files, installers, and known testing samples such as EICAR.
This detection leverages Cisco Secure Firewall Threat Defense logs and enriches the results using a filetype lookup to provide context.
If confirmed malicious, these downloads could indicate the initial infection vector, malware staging, or scripting abuse.


## MITRE ATT&CK

- T1203
- T1059

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics

## Data Sources

- Cisco Secure Firewall Threat Defense File Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/file_event/file_events.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___binary_file_type_download.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
