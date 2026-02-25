# Zscaler Potentially Abused File Download

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Rod Soto, Splunk

## Description

This dataset contains sample data for identifying the download of potentially malicious file types, such as .scr, .dll, .bat, and .lnk, within a network. It leverages web proxy logs from Zscaler, focusing on blocked actions and analyzing fields like deviceowner, user, urlcategory, url, dest, and filename. This activity is significant as these file types are often used to spread malware, posing a threat to network security. If confirmed malicious, this activity could lead to malware execution, data compromise, or further network infiltration.

## MITRE ATT&CK

- T1566

## Analytic Stories

- Zscaler Browser Proxy Threats

## Data Sources


## Sample Data

- **Source:** zscaler
  **Sourcetype:** zscalernss-web
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566/zscalar_web_proxy/zscalar_web_proxy.json


---

*Source: [Splunk Security Content](detections/web/zscaler_potentially_abused_file_download.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
