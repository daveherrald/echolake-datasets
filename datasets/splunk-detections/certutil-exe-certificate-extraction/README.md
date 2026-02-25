# Certutil exe certificate extraction

**Type:** TTP

**Author:** Rod Soto, Splunk

## Description

This dataset contains sample data for identifying the use of certutil.exe with arguments indicating the manipulation or extraction of certificates. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant because extracting certificates can allow attackers to sign new authentication tokens, particularly in federated environments like Windows ADFS. If confirmed malicious, this could enable attackers to forge authentication tokens, potentially leading to unauthorized access and privilege escalation within the network.

## Analytic Stories

- Windows Persistence Techniques
- Living Off The Land
- Cloud Federated Credential Abuse
- Compromised Windows Host
- Windows Certificate Services
- Storm-2460 CLFS Zero Day Exploitation

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/certutil_exe_certificate_extraction/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/certutil_exe_certificate_extraction.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
