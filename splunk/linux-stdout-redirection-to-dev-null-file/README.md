# Linux Stdout Redirection To Dev Null File

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects command-line activities that redirect stdout or stderr to the /dev/null file. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs. This behavior is significant as it can indicate attempts to hide command outputs, a technique observed in the CyclopsBlink malware to conceal modifications to iptables firewall settings. If confirmed malicious, this activity could allow an attacker to stealthily alter system configurations, potentially leading to unauthorized access or persistent control over the compromised machine.

## MITRE ATT&CK

- T1562.004

## Analytic Stories

- Cyclops Blink
- Data Destruction
- Industroyer2

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/cyclopsblink/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_stdout_redirection_to_dev_null_file.yml)*
