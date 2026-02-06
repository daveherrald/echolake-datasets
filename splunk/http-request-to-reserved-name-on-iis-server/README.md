# HTTP Request to Reserved Name on IIS Server

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

Detects attempts to exploit a request smuggling technique against IIS that leverages a Windows quirk where requests for reserved Windows device names such as "/con" trigger an early server response before the request body is received. When combined with a Content-Length desynchronization, this behavior can lead to a parsing confusion between frontend and backend.

## MITRE ATT&CK

- T1071.001
- T1190

## Analytic Stories

- HTTP Request Smuggling

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/request_smuggling/suricata_reserved_names.log


---

*Source: [Splunk Security Content](detections/web/http_request_to_reserved_name_on_iis_server.yml)*
