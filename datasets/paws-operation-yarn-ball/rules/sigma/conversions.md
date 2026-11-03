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

## Agent Simulation Script Launched by node.exe from a Public Folder
```splunk
source IN ("WinEventLog:Microsoft-Windows-Sysmon/Operational", "WinEventLog:Security") Image="*\node.exe" CommandLine="*openclaw_sim.js*"
```
```logql
{job=~"eventlog|winlog|windows|fluentbit.*"} | json | Image=~`(?i).*\node\.exe$` and CommandLine=~`(?i).*openclaw_sim\.js.*`
```
```lucene
(source:(WinEventLog\:Microsoft\-Windows\-Sysmon\/Operational OR WinEventLog\:Security)) AND (Image:*\node.exe AND CommandLine:*openclaw_sim.js*)
```

## System and Domain Discovery from the Agent Chain
```splunk
source IN ("WinEventLog:Microsoft-Windows-Sysmon/Operational", "WinEventLog:Security") ParentImage="*\node.exe" CommandLine IN ("*whoami*", "*hostname*", "*ipconfig*", "*systeminfo*", "*net user*", "*net group*", "*net view*")
```
```logql
{job=~"eventlog|winlog|windows|fluentbit.*"} | json | ParentImage=~`(?i).*\node\.exe$` and (CommandLine=~`(?i).*whoami.*` or CommandLine=~`(?i).*hostname.*` or CommandLine=~`(?i).*ipconfig.*` or CommandLine=~`(?i).*systeminfo.*` or CommandLine=~`(?i).*net\ user.*` or CommandLine=~`(?i).*net\ group.*` or CommandLine=~`(?i).*net\ view.*`)
```
```lucene
(source:(WinEventLog\:Microsoft\-Windows\-Sysmon\/Operational OR WinEventLog\:Security)) AND (ParentImage:*\node.exe AND (CommandLine:(*whoami* OR *hostname* OR *ipconfig* OR *systeminfo* OR *net\ user* OR *net\ group* OR *net\ view*)))
```

## Scripted Agent Contacts the yarn-ball.xyz Lab Domain
```splunk
source IN ("WinEventLog:Microsoft-Windows-Sysmon/Operational", "WinEventLog:Security") CommandLine="*yarn-ball.xyz*"
```
```logql
{job=~"eventlog|winlog|windows|fluentbit.*"} | json | CommandLine=~`(?i).*yarn\-ball\.xyz.*`
```
```lucene
(source:(WinEventLog\:Microsoft\-Windows\-Sysmon\/Operational OR WinEventLog\:Security)) AND CommandLine:*yarn\-ball.xyz*
```

## WindowsUpdate-Named Scheduled Task for a Temp-Folder Binary
```splunk
source IN ("WinEventLog:Microsoft-Windows-Sysmon/Operational", "WinEventLog:Security") Image="*\schtasks.exe" CommandLine="*/create*" CommandLine="*WindowsUpdate*" CommandLine="*patch-kb5041234.exe*"
```
```logql
{job=~"eventlog|winlog|windows|fluentbit.*"} | json | Image=~`(?i)*\schtasks\.exe$` and CommandLine=~`(?i).*/create.*` and CommandLine=~`(?i).*WindowsUpdate.*` and CommandLine=~`(?i).*patch\-kb5041234\.exe.*`
```
```lucene
(source:(WinEventLog\:Microsoft\-Windows\-Sysmon\/Operational OR WinEventLog\:Security)) AND (Image:*\schtasks.exe AND (CommandLine:*\/create* AND CommandLine:*WindowsUpdate* AND CommandLine:*patch\-kb5041234.exe*))
```

## Execution of the Temp-Staged Patch-Named Binary
```splunk
source IN ("WinEventLog:Microsoft-Windows-Sysmon/Operational", "WinEventLog:Security") Image="*\patch-kb5041234.exe" Image="*\Windows\Temp\*"
```
```logql
{job=~"eventlog|winlog|windows|fluentbit.*"} | json | Image=~`(?i).*\patch\-kb5041234\.exe$` and Image=~`(?i).*\Windows\Temp\.*`
```
```lucene
(source:(WinEventLog\:Microsoft\-Windows\-Sysmon\/Operational OR WinEventLog\:Security)) AND (Image:*\patch\-kb5041234.exe AND Image:*\Windows\Temp\*)
```

## Outbound Connection to the Lab Retrieval Host on Port 9090
```splunk
source IN ("zeek_conn", "/opt/zeek/logs/current/conn.log") id.resp_p=9090
```
```logql
{job=~".+"} | json | id_resp_p=9090
```
```lucene
(source:(zeek_conn OR \/opt\/zeek\/logs\/current\/conn.log)) AND id.resp_p:9090
```
