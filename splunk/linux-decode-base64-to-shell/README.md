# Linux Decode Base64 to Shell

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the behavior of decoding base64-encoded data and passing it to a Linux shell. Additionally, it mitigates the potential damage and protects the organization's systems and data.The detection is made by searching for specific commands in the Splunk query, namely "base64 -d" and "base64 --decode", within the Endpoint.Processes data model. The analytic also includes a filter for Linux shells. The detection is important because  it indicates the presence of malicious activity since Base64 encoding is commonly used to obfuscate malicious commands or payloads, and decoding it can be a step in running those commands. It suggests that an attacker is attempting to run malicious commands on a Linux system to gain unauthorized access, for data exfiltration, or perform other malicious actions.

## MITRE ATT&CK

- T1027
- T1059.004

## Analytic Stories

- Linux Living Off The Land
- Cisco Isovalent Suspicious Activity

## Data Sources

- Sysmon for Linux EventID 1
- Cisco Isovalent Process Exec

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1027/atomic_red_team/linux-sysmon.log

- **Source:** not_applicable
  **Sourcetype:** cisco:isovalent:processExec
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_isovalent/cisco_isovalent.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_decode_base64_to_shell.yml)*
