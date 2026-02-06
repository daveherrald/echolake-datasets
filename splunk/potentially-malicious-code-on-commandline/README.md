# Potentially malicious code on commandline

**Type:** Anomaly

**Author:** Michael Hart, Splunk

## Description

The following analytic detects potentially malicious command lines using a pretrained machine learning text classifier. It identifies unusual keyword combinations in command lines, such as "streamreader," "webclient," "mutex," "function," and "computehash," which are often associated with adversarial PowerShell code execution for C2 communication. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on command lines longer than 200 characters. This activity is significant as it can indicate an attempt to execute malicious scripts, potentially leading to unauthorized code execution, data exfiltration, or further system compromise.

## MITRE ATT&CK

- T1059.003

## Analytic Stories

- Suspicious Command-Line Executions

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/malicious_cmd_line_samples/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/potentially_malicious_code_on_commandline.yml)*
