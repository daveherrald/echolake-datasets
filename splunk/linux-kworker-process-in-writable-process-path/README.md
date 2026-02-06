# Linux Kworker Process In Writable Process Path

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of a kworker process with a command line in writable directories such as /home/, /var/log, and /tmp on a Linux machine. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and parent process paths. This activity is significant as kworker processes are typically kernel threads, and their presence in writable directories is unusual and indicative of potential malware, such as CyclopsBlink. If confirmed malicious, this could allow attackers to blend malicious processes with legitimate ones, leading to persistent access and further system compromise.

## MITRE ATT&CK

- T1036.004

## Analytic Stories

- Sandworm Tools
- Cyclops Blink

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/cyclopsblink/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_kworker_process_in_writable_process_path.yml)*
