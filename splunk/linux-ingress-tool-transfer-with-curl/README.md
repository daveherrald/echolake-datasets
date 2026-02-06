# Linux Ingress Tool Transfer with Curl

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of the curl command with specific switches (-O, -sO, -ksO, --output) commonly used to download remote scripts or binaries. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant as it may indicate an attempt to download and execute potentially malicious files, often used in initial stages of an attack. If confirmed malicious, this could lead to unauthorized code execution, enabling attackers to compromise the system further.

## MITRE ATT&CK

- T1105

## Analytic Stories

- Ingress Tool Transfer
- Linux Living Off The Land
- XorDDos
- NPM Supply Chain Compromise

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/curl-linux-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_ingress_tool_transfer_with_curl.yml)*
