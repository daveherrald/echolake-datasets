# Suspicious Linux Discovery Commands

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

The following analytic detects the execution of suspicious bash commands commonly used in scripts like AutoSUID, LinEnum, and LinPeas for system discovery on a Linux host. It leverages Endpoint Detection and Response (EDR) data, specifically looking for a high number of distinct commands executed within a short time frame. This activity is significant as it often precedes privilege escalation or other malicious actions. If confirmed malicious, an attacker could gain detailed system information, identify vulnerabilities, and potentially escalate privileges, posing a severe threat to the environment.

## MITRE ATT&CK

- T1059.004

## Analytic Stories

- Linux Post-Exploitation
- VoidLink Cloud-Native Linux Malware

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.004/linux_discovery_tools/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_linux_discovery_commands.yml)*
