# Operation Yarn Ball rule conversions

Generated with sigma-cli; see `pipelines/paws_logsources.yml` for the Splunk/Lucene source mapping (Loki needs none). Replace the source paths with your own index or sourcetype.

## Defender Exclusions for the Staging Directory and Patch Binary
```splunk
source="WinEventLog:Microsoft-Windows-PowerShell/Operational" ScriptBlockText="*Add-MpPreference*" ScriptBlockText="*Exclusion*"
```
```logql
{job=~"eventlog|winlog|windows|fluentbit.*"} | json | ScriptBlockText=~`(?i).*Add\-MpPreference.*` and ScriptBlockText=~`(?i).*Exclusion.*`
```
```lucene
source:WinEventLog\:Microsoft\-Windows\-PowerShell\/Operational AND (ScriptBlockText:*Add\-MpPreference* AND ScriptBlockText:*Exclusion*)
```
