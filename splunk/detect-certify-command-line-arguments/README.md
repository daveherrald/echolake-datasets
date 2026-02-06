# Detect Certify Command Line Arguments

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic detects the use of Certify or Certipy tools to enumerate Active Directory Certificate Services (AD CS) environments. It leverages Endpoint Detection and Response (EDR) data, focusing on specific command-line arguments associated with these tools. This activity is significant because it indicates potential reconnaissance or exploitation attempts targeting AD CS, which could lead to unauthorized access or privilege escalation. If confirmed malicious, attackers could gain insights into the AD CS infrastructure, potentially compromising sensitive certificates and escalating their privileges within the network.

## MITRE ATT&CK

- T1649
- T1105

## Analytic Stories

- Compromised Windows Host
- Windows Certificate Services
- Ingress Tool Transfer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1649/certify_abuse/certify_esc1_abuse_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_certify_command_line_arguments.yml)*
