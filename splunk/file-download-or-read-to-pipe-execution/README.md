# File Download or Read to Pipe Execution

**Type:** TTP

**Author:** Michael Haag, Nasreddine Bencherchali, Splunk, DipsyTipsy

## Description

The following analytic detects the use of download or file reading utilities from Windows, Linux or MacOS to download or read the contents of a file from a remote or local source and pipe it directly to a shell for execution.
This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions.
This activity is significant as it is commonly associated with malicious actions like coinminers and exploits such as CVE-2021-44228 in Log4j.
If confirmed malicious, this behavior could allow attackers to execute arbitrary code, potentially leading to system compromise and unauthorized access to sensitive data.


## MITRE ATT&CK

- T1105

## Analytic Stories

- Compromised Windows Host
- Ingress Tool Transfer
- Linux Living Off The Land
- Log4Shell CVE-2021-44228
- NPM Supply Chain Compromise

## Data Sources

- Sysmon EventID 1
- Sysmon for Linux EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/download_to_pipe_exec/download_to_pipe_exec.log

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/download_to_pipe_exec/download_to_pipe_exec_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/file_download_or_read_to_pipe_execution.yml)*
