# cloud-data-exfiltration rule conversions

Generated with sigma-cli; see `pipelines/cloudexfil_logsources.yml` for the Splunk/Lucene source mapping (Loki needs none). Replace the source paths with your own index or sourcetype.

## GitHub Secret-Scanning Alert for a Leaked SSH Private Key
```splunk
source="github:audit" action="secret_scanning_alert.create" secret_types="*ssh_private_key*"
```
```logql
{job=~".+"} | logfmt | action=~`(?i)^secret_scanning_alert\.create$` and secret_types=~`(?i).*ssh_private_key.*`
```
```lucene
source:github\:audit AND (action:secret_scanning_alert.create AND secret_types:*ssh_private_key*)
```
