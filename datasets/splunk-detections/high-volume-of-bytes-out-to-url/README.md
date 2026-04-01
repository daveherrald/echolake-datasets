# High Volume of Bytes Out to Url

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for detecting a high volume of outbound web traffic, specifically over 1GB of data sent to a URL within a 2-minute window. It leverages the Web data model to identify significant uploads by analyzing the sum of bytes out. This activity is significant as it may indicate potential data exfiltration by malware or malicious insiders. If confirmed as malicious, this behavior could lead to unauthorized data transfer, resulting in data breaches and loss of sensitive information. Immediate investigation is required to determine the legitimacy of the transfer and mitigate any potential threats.

## MITRE ATT&CK

- T1567

## Analytic Stories

- Data Exfiltration
- Hellcat Ransomware

## Data Sources

- Nginx Access

## Sample Data

- **Source:** /var/log/nginx/access.log
  **Sourcetype:** nginx:plus:kv
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1567/web_upload_nginx/web_upload_nginx.log


---

*Source: [Splunk Security Content](detections/web/high_volume_of_bytes_out_to_url.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
