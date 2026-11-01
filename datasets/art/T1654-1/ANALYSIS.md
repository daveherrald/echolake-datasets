# T1654-1: Get-EventLog To Enumerate Windows Security Log

## Technique Context

Atomic Red Team T1654 test 1 searches the Windows Security log for messages containing `SYSTEM` and exports matching entries to a file in the temporary directory.

## Packaged Telemetry

The five bundled files contain 33,758 events from `2026-03-14T14:46:33.003000Z` through `2026-03-14T14:46:41.442000Z`.

| Channel | Events |
|---|---:|
| Security | 32,608 |
| Application | 6 |
| PowerShell | 1,094 |
| Sysmon | 49 |
| WMI | 1 |

PowerShell EID 4104 records the technique command at `2026-03-14T14:46:37.250000Z`:

```powershell
get-eventlog 'Security' | where {$_.Message -like '*SYSTEM*'} | export-csv $env:temp\T1654_events.txt
```

Sysmon EID 1 records the PowerShell wrapper at `2026-03-14T14:46:37.011000Z` and its encoded child PowerShell process at `2026-03-14T14:46:37.147000Z`. Sysmon EID 11 records creation of `C:\Windows\Temp\T1654_events.txt` at `2026-03-14T14:46:37.325000Z`.

The Security payload contains 32,600 EID 4703 events and 8 EID 4689 events. These counts describe the captured channel. They do not, by themselves, establish which Security records matched the PowerShell filter or what was written to the CSV file.

## Assessment

This package contains direct command and file-creation evidence for the log-enumeration test. PowerShell EID 4104 provides the clearest technique signal. Sysmon process creation and file creation provide supporting evidence for the child PowerShell execution and export destination.

Detection logic can match `Get-EventLog` against the Security log, a `SYSTEM` message filter, or export to `T1654_events.txt`. File creation alone should be correlated with the PowerShell command because the package does not preserve the exported file contents.
