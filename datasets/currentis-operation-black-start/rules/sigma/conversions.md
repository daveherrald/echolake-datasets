# Operation Black Start rule conversions

Generated with sigma-cli; see `pipelines/currentis_logsources.yml` for the Splunk/Lucene source mapping (Loki needs none). Replace the source paths with your own index or sourcetype.

## AI Coding Assistant Spawns a Windows Shell
```splunk
source IN ("WinEventLog:Microsoft-Windows-Sysmon/Operational", "WinEventLog:Security") ParentImage="*\\node.exe" Image IN ("*\\powershell.exe", "*\\cmd.exe")
```
```logql
{job=~"eventlog|winlog|windows|fluentbit.*"} | json | ParentImage=~`(?i).*\\node\.exe$` and (Image=~`(?i).*\\powershell\.exe$` or Image=~`(?i).*\\cmd\.exe$`)
```
```lucene
(source:(WinEventLog\:Microsoft\-Windows\-Sysmon\/Operational OR WinEventLog\:Security)) AND (ParentImage:*\\node.exe AND (Image:(*\\powershell.exe OR *\\cmd.exe)))
```

## Living-off-the-Land Active Directory Recon Burst
```splunk
source IN ("WinEventLog:Microsoft-Windows-Sysmon/Operational", "WinEventLog:Security") CommandLine IN ("*whoami /all*", "*group /domain*", "*user /domain*", "*nltest /dclist*", "*helixgrid-svc /domain*")
```
```logql
{job=~"eventlog|winlog|windows|fluentbit.*"} | json | CommandLine=~`(?i).*whoami\ /all.*` or CommandLine=~`(?i).*group\ /domain.*` or CommandLine=~`(?i).*user\ /domain.*` or CommandLine=~`(?i).*nltest\ /dclist.*` or CommandLine=~`(?i).*helixgrid\-svc\ /domain.*`
```
```lucene
(source:(WinEventLog\:Microsoft\-Windows\-Sysmon\/Operational OR WinEventLog\:Security)) AND (CommandLine:(*whoami\ \/all* OR *group\ \/domain* OR *user\ \/domain* OR *nltest\ \/dclist* OR *helixgrid\-svc\ \/domain*))
```

## Masqueraded Windows Update Binary in Public Folder
```splunk
source IN ("WinEventLog:Microsoft-Windows-Sysmon/Operational", "WinEventLog:Security") Image="*\\kb5041234-v3.exe" Image="*\\Users\\Public\\*"
```
```logql
{job=~"eventlog|winlog|windows|fluentbit.*"} | json | Image=~`(?i).*\\kb5041234\-v3\.exe$` and Image=~`(?i).*\\Users\\Public\\.*`
```
```lucene
(source:(WinEventLog\:Microsoft\-Windows\-Sysmon\/Operational OR WinEventLog\:Security)) AND (Image:*\\kb5041234\-v3.exe AND Image:*\\Users\\Public\\*)
```

## Sliver HTTP Beacon User-Agent to C2
```splunk
source IN ("zeek_http", "/opt/zeek/logs/current/http.log") user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.8287.614 Safari/537.36" id.resp_h="121.43.243.13"
```
```logql
{job=~".+"} | json | user_agent=~`(?i)^Mozilla/5\.0\ \(Windows\ NT\ 10\.0;\ Win64;\ x64\)\ AppleWebKit/537\.36\ \(KHTML,\ like\ Gecko\)\ Chrome/106\.0\.8287\.614\ Safari/537\.36$` and id_resp_h=~`(?i)^121\.43\.243\.13$`
```
```lucene
(source:(zeek_http OR \/opt\/zeek\/logs\/current\/http.log)) AND (user_agent:"Mozilla\/5.0 \(Windows NT 10.0; Win64; x64\) AppleWebKit\/537.36 \(KHTML, like Gecko\) Chrome\/106.0.8287.614 Safari\/537.36" AND id.resp_h:121.43.243.13)
```

## Outbound Connection to Known C2 Indicator
```splunk
source IN ("zeek_conn", "/opt/zeek/logs/current/conn.log") id.resp_h="121.43.243.13"
```
```logql
{job=~".+"} | json | id_resp_h=~`(?i)^121\.43\.243\.13$`
```
```lucene
(source:(zeek_conn OR \/opt\/zeek\/logs\/current\/conn.log)) AND id.resp_h:121.43.243.13
```

## Implant Run-Key Persistence (CLIENTSYNC)
```splunk
TargetObject="*\\CurrentVersion\\Run\\*" Details="*clientsync.ps1*"
```
```logql
{job=~"eventlog|winlog|windows|fluentbit.*"} | json | TargetObject=~`(?i).*\\CurrentVersion\\Run\\.*` and Details=~`(?i).*clientsync\.ps1.*`
```
```lucene
TargetObject:*\\CurrentVersion\\Run\\* AND Details:*clientsync.ps1*
```

## LSASS Memory Access from Masqueraded Update Binary
```splunk
TargetImage="*\\lsass.exe" SourceImage="*\\kb5041234-v3.exe"
```
```logql
{job=~"eventlog|winlog|windows|fluentbit.*"} | json | TargetImage=~`(?i).*\\lsass\.exe$` and SourceImage=~`(?i).*\\kb5041234\-v3\.exe$`
```
```lucene
TargetImage:*\\lsass.exe AND SourceImage:*\\kb5041234\-v3.exe
```

## Stolen Vendor Credential Staged with cmdkey for RDP
```splunk
source IN ("WinEventLog:Microsoft-Windows-Sysmon/Operational", "WinEventLog:Security") Image="*\\cmdkey.exe" CommandLine="*/generic:TERMSRV/*" CommandLine="*helixgrid-svc*"
```
```logql
{job=~"eventlog|winlog|windows|fluentbit.*"} | json | Image=~`(?i).*\\cmdkey\.exe$` and CommandLine=~`(?i).*/generic:TERMSRV/.*` and CommandLine=~`(?i).*helixgrid\-svc.*`
```
```lucene
(source:(WinEventLog\:Microsoft\-Windows\-Sysmon\/Operational OR WinEventLog\:Security)) AND (Image:*\\cmdkey.exe AND (CommandLine:*\/generic\:TERMSRV\/* AND CommandLine:*helixgrid\-svc*))
```

## Vendor Service Account RDP Logon to OT Jump Host
```splunk
source="WinEventLog:Security" EventID=4624 LogonType=10 TargetUserName="helixgrid-svc"
```
```logql
{job=~"eventlog|winlog|windows|fluentbit.*"} | json | EventID=4624 and LogonType=10 and TargetUserName=~`(?i)^helixgrid\-svc$`
```
```lucene
source:WinEventLog\:Security AND (EventID:4624 AND LogonType:10 AND TargetUserName:helixgrid\-svc)
```

## OT Turbine Configuration File Access by Vendor Account
```splunk
source="WinEventLog:Security" EventID=4663 ObjectName IN ("*\\OT\\*", "*Helix Grid Systems*")
```
```logql
{job=~"eventlog|winlog|windows|fluentbit.*"} | json | EventID=4663 and (ObjectName=~`(?i).*\\OT\\.*` or ObjectName=~`(?i).*Helix\ Grid\ Systems.*`)
```
```lucene
source:WinEventLog\:Security AND (EventID:4663 AND (ObjectName:(*\\OT\\* OR *Helix\ Grid\ Systems*)))
```

## Scheduled Task Launching a Script from a World-Writable Path
```splunk
source IN ("WinEventLog:Microsoft-Windows-Sysmon/Operational", "WinEventLog:Security") Image="*\\schtasks.exe" CommandLine="*/create*" CommandLine IN ("*\\Users\\Public\\*", "*read_ot.ps1*", "*helixgrid-svc*")
```
```logql
{job=~"eventlog|winlog|windows|fluentbit.*"} | json | Image=~`(?i).*\\schtasks\.exe$` and CommandLine=~`(?i).*/create.*` and (CommandLine=~`(?i).*\\Users\\Public\\.*` or CommandLine=~`(?i).*read_ot\.ps1.*` or CommandLine=~`(?i).*helixgrid\-svc.*`)
```
```lucene
(source:(WinEventLog\:Microsoft\-Windows\-Sysmon\/Operational OR WinEventLog\:Security)) AND ((Image:*\\schtasks.exe AND CommandLine:*\/create*) AND (CommandLine:(*\\Users\\Public\\* OR *read_ot.ps1* OR *helixgrid\-svc*)))
```

## Security Event Log Cleared with wevtutil
```splunk
source IN ("WinEventLog:Microsoft-Windows-Sysmon/Operational", "WinEventLog:Security") Image="*\\wevtutil.exe" CommandLine="* cl *" CommandLine="*Security*"
```
```logql
{job=~"eventlog|winlog|windows|fluentbit.*"} | json | Image=~`(?i).*\\wevtutil\.exe$` and CommandLine=~`(?i).*\ cl\ .*` and CommandLine=~`(?i).*Security.*`
```
```lucene
(source:(WinEventLog\:Microsoft\-Windows\-Sysmon\/Operational OR WinEventLog\:Security)) AND (Image:*\\wevtutil.exe AND (CommandLine:*\ cl\ * AND CommandLine:*Security*))
```

## Windows Security Audit Log Cleared (Event 1102)
```splunk
source="WinEventLog:Security" EventID=1102
```
```logql
{job=~"eventlog|winlog|windows|fluentbit.*"} | json | EventID=1102
```
```lucene
source:WinEventLog\:Security AND EventID:1102
```

