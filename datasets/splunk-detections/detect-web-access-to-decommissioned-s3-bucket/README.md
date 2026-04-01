# Detect Web Access to Decommissioned S3 Bucket

**Type:** Anomaly

**Author:** Jose Hernandez, Splunk

## Description

This detection identifies web requests to domains that match previously decommissioned S3 buckets through web proxy logs. This activity is significant because attackers may attempt to access or recreate deleted S3 buckets that were previously public to hijack them for malicious purposes. If successful, this could allow attackers to host malicious content or exfiltrate data through compromised bucket names that may still be referenced by legitimate applications.

## MITRE ATT&CK

- T1485

## Analytic Stories

- AWS S3 Bucket Security Monitoring
- Data Destruction

## Data Sources

- AWS Cloudfront

## Sample Data

- **Source:** cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/decommissioned_buckets/cloudtrail.json

- **Source:** aws_cloudfront_accesslogs
  **Sourcetype:** aws:cloudfront:accesslogs
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/decommissioned_buckets/web_cloudfront_access.log


---

*Source: [Splunk Security Content](detections/web/detect_web_access_to_decommissioned_s3_bucket.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
