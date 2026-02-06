# Cisco NVM - Webserver Download From File Sharing Website

**Type:** TTP

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects unexpected outbound network connections initiated by known webserver processes such as `httpd.exe`, `nginx.exe`, or `tomcat.exe` to common file sharing or public content hosting services like GitHub, Discord CDN, Transfer.sh, or Pastebin.
Webservers are rarely expected to perform outbound downloads, especially to dynamic or anonymous file hosting domains. This behavior is often associated with server compromise,
where an attacker uses a reverse shell, webshell, or injected task to fetch malware or tools post-exploitation.
The detection leverages Cisco Network Visibility Module flow data, enriched with process context, to identify this highly suspicious behavior.


## MITRE ATT&CK

- T1105
- T1190

## Analytic Stories

- GhostRedirector IIS Module and Rungan Backdoor
- Cisco Network Visibility Module Analytics

## Data Sources

- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_nvm___webserver_download_from_file_sharing_website.yml)*
