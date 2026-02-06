# Linux System Reboot Via System Request Key

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the SysReq hack to reboot a Linux system host. It leverages Endpoint Detection and Response (EDR) data to identify processes executing the command to pipe 'b' to /proc/sysrq-trigger. This activity is significant as it is an uncommon method to reboot a system and was observed in the Awfulshred malware wiper. If confirmed malicious, this technique could indicate the presence of suspicious processes and potential system compromise, leading to unauthorized reboots and disruption of services.

## MITRE ATT&CK

- T1529

## Analytic Stories

- AwfulShred
- Data Destruction

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/awfulshred/test2/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_system_reboot_via_system_request_key.yml)*
