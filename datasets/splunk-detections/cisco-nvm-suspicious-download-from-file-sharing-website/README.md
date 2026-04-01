# Cisco NVM - Suspicious Download From File Sharing Website

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects suspicious downloads from common file sharing and content delivery platforms using known living-off-the-land binaries (LOLBins)
such as 'curl.exe', 'certutil.exe', 'msiexec.exe', 'powershell.exe', 'wmic.exe', and others.
It leverages Cisco Network Visibility Module logs to correlate network flow activity with process context, including command-line arguments, process path,
and parent process information. These tools are often abused by adversaries and malware to retrieve payloads from public hosting platforms
such as GitHub, Discord CDN, Transfer.sh, or Pastebin.
This detection helps identify potential initial access, payload staging, or command and control activity using legitimate services.


## MITRE ATT&CK

- T1197

## Analytic Stories

- APT37 Rustonotto and FadeStealer
- Cisco Network Visibility Module Analytics

## Data Sources

- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_nvm___suspicious_download_from_file_sharing_website.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
