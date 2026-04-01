# Cisco Isovalent - Kprobe Spike

**Type:** Hunting

**Author:** Bhavin Patel, Splunk

## Description

This analytic detects excessive kernel probe (kprobe) events in a Kubernetes cluster over a short period of time. 
Kprobes are a Linux kernel debugging and instrumentation mechanism that allows dynamic monitoring and tracing of kernel functions and system calls. 
In containerized or cloud-native environments, kprobes are occasionally used for legitimate low-level diagnostics; however, monitoring a spike in kprobe activity is important because malware or attackers may abuse this mechanism to gain insights into the kernel, attempt privilege escalation, or tamper with host processes. 
More than 10 kprobe events within 5 minutes may indicate suspicious activity, such as an attacker probing the kernel through repeated system calls (e.g., nsenter, mount, sethostname). 
Such abnormal volume and frequency of kprobe usage within application pods or on nodes can signal container escape attempts or low-level tampering with the host, thereby representing a potential security threat.


## MITRE ATT&CK

- T1068

## Analytic Stories

- Cisco Isovalent Suspicious Activity
- VoidLink Cloud-Native Linux Malware

## Data Sources

- Cisco Isovalent Process Kprobe

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:isovalent
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_isovalent/kprobe_spike.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_isovalent___kprobe_spike.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
