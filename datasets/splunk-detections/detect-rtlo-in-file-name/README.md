# Detect RTLO In File Name

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for identifying the use of the right-to-left override
(RTLO) character in file names. It leverages data from the Endpoint.Filesystem datamodel,
specifically focusing on file creation events and file names containing the RTLO
character (U+202E). This activity is significant because adversaries use RTLO to
disguise malicious files as benign by reversing the text that follows the character.
If confirmed malicious, this technique can deceive users and security tools, leading
to the execution of harmful files and potential system compromise.


## MITRE ATT&CK

- T1036.002

## Analytic Stories

- Spearphishing Attachments

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.002/outlook_attachment/rtlo_events.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_rtlo_in_file_name.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
