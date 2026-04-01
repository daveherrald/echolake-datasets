# Detect Spike in AWS Security Hub Alerts for EC2 Instance

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for identifying a spike in the number of AWS Security Hub alerts for an EC2 instance within a 4-hour interval. It leverages AWS Security Hub findings data, calculating the average and standard deviation of alerts to detect anomalies. This activity is significant for a SOC as a sudden increase in alerts may indicate potential security incidents or misconfigurations requiring immediate attention. If confirmed malicious, this could signify an ongoing attack, leading to unauthorized access, data exfiltration, or disruption of services on the affected EC2 instance.

## Analytic Stories

- AWS Security Hub Alerts
- Critical Alerts

## Data Sources

- AWS Security Hub

## Sample Data

- **Source:** aws_securityhub_finding
  **Sourcetype:** aws:securityhub:finding
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/security_hub_ec2_spike/security_hub_ec2_spike.json


---

*Source: [Splunk Security Content](detections/cloud/detect_spike_in_aws_security_hub_alerts_for_ec2_instance.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
