# Linux Proxy Socks Curl

**Type:** TTP

**Author:** Michael Haag, Splunk, 0xC0FFEEEE, Github Community

## Description

The following analytic detects the use of the `curl` command with proxy-related arguments such as `-x`, `socks`, `--preproxy`, and `--proxy`. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions and process details. This activity is significant as it may indicate an adversary attempting to use a proxy to evade network monitoring and obscure their actions. If confirmed malicious, this behavior could allow attackers to bypass security controls, making it difficult to track their activities and potentially leading to unauthorized data access or exfiltration.

## MITRE ATT&CK

- T1090
- T1095

## Analytic Stories

- Linux Living Off The Land
- Ingress Tool Transfer

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/curl-linux-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_proxy_socks_curl.yml)*
