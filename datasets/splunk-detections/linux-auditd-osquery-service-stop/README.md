# Linux Auditd Osquery Service Stop

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious stopping of the `osquery` service, which may indicate an attempt to disable monitoring and evade detection. `Osquery` is a powerful tool used for querying system information and detecting anomalies, and stopping its service can be a sign that an attacker is trying to disrupt security monitoring or hide malicious activities. By monitoring for unusual or unauthorized stops of the `osquery` service, this analytic helps identify potential efforts to bypass security controls, enabling security teams to investigate and respond to possible threats effectively.

## MITRE ATT&CK

- T1489

## Analytic Stories

- Linux Living Off The Land
- Linux Privilege Escalation
- Linux Persistence Techniques
- Compromised Linux Host

## Data Sources

- Linux Auditd Service Stop

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1489/linux_auditd_osquerd_service_stop/linux_auditd_osquerd_service_stop.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_osquery_service_stop.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
