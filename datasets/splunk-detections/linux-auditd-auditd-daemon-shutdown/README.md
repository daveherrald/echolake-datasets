# Linux Auditd Auditd Daemon Shutdown

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the unexpected termination of the Linux Audit daemon (auditd) by monitoring for log entries of type DAEMON_END. This event signifies that the audit logging service has stopped, either due to a legitimate system shutdown, manual administrative action, or potentially malicious tampering. Since auditd is responsible for recording critical security events, its sudden stoppage may indicate an attempt to disable security monitoring or evade detection during an attack. This detection should be correlated with system logs to determine whether the shutdown was part of routine maintenance or an anomaly. If confirmed as malicious, this could lead to a compromised system where security events are no longer being logged, allowing attackers to operate undetected. Therefore, monitoring and alerting on auditd shutdown events is crucial for maintaining the integrity of system security monitoring.

## MITRE ATT&CK

- T1562.012

## Analytic Stories

- Compromised Linux Host

## Data Sources

- Linux Auditd Daemon End

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.012/auditd_daemon_end/linux_daemon_end.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_auditd_daemon_shutdown.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
