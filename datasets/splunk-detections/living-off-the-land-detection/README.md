# Living Off The Land Detection

**Type:** Correlation

**Author:** Michael Haag, Splunk

## Description

The following correlation identifies multiple risk events associated with the "Living Off The Land" analytic story, indicating potentially suspicious behavior. It leverages the Risk data model to aggregate and correlate events tagged under this story, focusing on systems with a high count of distinct sources. This activity is significant as it often involves the use of legitimate tools for malicious purposes, making detection challenging. If confirmed malicious, this behavior could allow attackers to execute code, escalate privileges, or persist within the environment using trusted system utilities.

## MITRE ATT&CK

- T1105
- T1190
- T1059
- T1133

## Analytic Stories

- Living Off The Land
- Hellcat Ransomware

## Data Sources


## Sample Data

- **Source:** lotl
  **Sourcetype:** stash
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218/living_off_the_land/lolbinrisk.log


---

*Source: [Splunk Security Content](detections/endpoint/living_off_the_land_detection.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
