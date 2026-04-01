# SAM Database File Access Attempt

**Type:** Hunting

**Author:** Michael Haag, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting attempts to access the SAM, SYSTEM, or SECURITY database files within the `windows\system32\config` directory using Windows Security EventCode 4663. This detection leverages Windows Security Event logs to identify unauthorized access attempts. Monitoring this activity is crucial as it indicates potential credential access attempts, possibly exploiting vulnerabilities like CVE-2021-36934. If confirmed malicious, an attacker could extract user passwords, leading to unauthorized access, privilege escalation, and further compromise of the system.

## MITRE ATT&CK

- T1003.002

## Analytic Stories

- Credential Dumping
- Graceful Wipe Out Attack
- Rhysida Ransomware

## Data Sources

- Windows Event Log Security 4663

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.002/serioussam/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/sam_database_file_access_attempt.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
