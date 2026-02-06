# Cisco NVM - Suspicious File Download via Headless Browser

**Type:** TTP

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic identifies the use of Chromium-based browsers (like Microsoft Edge) running in headless mode with the `--dump-dom` argument.
This behavior has been observed in attack campaigns such as DUCKTAIL, where browsers are automated to stealthily download content from the internet using direct URLs or suspicious hosting platforms.
The detection focuses on identifying connections to known file-sharing domains or direct IPs extracted from command-line arguments and cross-checks those against the destination of the flow.
Since it leverages Cisco Network Visibility Module telemetry, the rule triggers only if a network connection is made.


## MITRE ATT&CK

- T1105
- T1059

## Analytic Stories

- Cisco Network Visibility Module Analytics

## Data Sources

- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_nvm___suspicious_file_download_via_headless_browser.yml)*
