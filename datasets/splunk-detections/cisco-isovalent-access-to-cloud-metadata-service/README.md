# Cisco Isovalent - Access To Cloud Metadata Service

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for detecting workloads accessing the cloud instance metadata service at 169.254.169.254. This IP is used by AWS, GCP and Azure metadata endpoints and is frequently abused in SSRF or lateral movement scenarios to obtain credentials and sensitive environment details. Monitor unexpected access to this service from application pods or namespaces where such behavior is atypical.

## MITRE ATT&CK

- T1552.005

## Analytic Stories

- Cisco Isovalent Suspicious Activity
- VoidLink Cloud-Native Linux Malware

## Data Sources

- Cisco Isovalent Process Connect

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:isovalent:processConnect
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.005/isovalent_cloud_metadata/process_connect.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_isovalent___access_to_cloud_metadata_service.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
