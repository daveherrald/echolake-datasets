# T1562.001-23: Disable or Modify Tools — Tamper with Windows Defender Evade Scanning - Folder

## Technique Context

MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) includes adding exclusions
to Windows Defender rather than disabling it outright. Path-based exclusions instruct Defender
to skip scanning of an entire directory tree. Adversaries add a staging directory to Defender's
exclusion list before dropping malware into it, creating a safe zone for tools and payloads.
This approach is subtler than disabling Defender entirely and may not trigger Tamper
Protection, since the `Add-MpPreference` cmdlet is an officially supported API. The
technique is widely used by commodity malware, loaders, and hands-on-keyboard operators.

## What This Dataset Contains

The dataset captures 38 Sysmon events, 13 Security events, and 40 PowerShell events spanning
approximately 6 seconds on ACME-WS02 (Windows 11 Enterprise, domain member of acme.local).

The attack payload is concise and clearly visible across all three log sources. PowerShell
4104 script block logging records:

```powershell
$excludedpath= "C:\Temp"
Add-MpPreference -ExclusionPath $excludedpath
```

Sysmon EID 1 captures the child PowerShell process create with the full command line:

```
"powershell.exe" & {$excludedpath= "C:\Temp"
Add-MpPreference -ExclusionPath $excludedpath}
```

The `Add-MpPreference` call triggers loading of the Defender management module, which
produces a large number of PowerShell 4104 events containing the full module parameter
definitions (28 chunks totaling the module's parameter manifest). This is standard behavior
when PowerShell loads a compiled module for the first time in a session — the entire module
definition is logged by script block logging.

Security 4689 exit events show `MpCmdRun.exe` exiting with **status 0x0**, confirming
the exclusion was applied successfully. The standard ART test framework preamble is present.

## What This Dataset Does Not Contain (and Why)

**No Sysmon EID 13 (registry write) for the exclusion.** The `Add-MpPreference` cmdlet
applies the exclusion via the Defender WMI provider or internal COM interface rather than
writing directly to the registry. The exclusion is stored at
`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\`, but the write path goes
through a privileged service component that Sysmon may not intercept as a simple registry
write, depending on the access method used. Only the PowerShell execution events and the
process chain are present.

**No Windows Defender operational log entries.** Defender operational events (in the
Microsoft-Windows-Windows Defender/Operational channel) would record the exclusion being
added. This channel is not collected in this dataset.

**No file system activity in C:\Temp.** The test adds the exclusion but does not place
any payload in the excluded directory. No Sysmon EID 11 events for `C:\Temp` appear.

**Sysmon ProcessCreate is filtered.** Only PowerShell is captured via EID 1; the
`MpCmdRun.exe` subprocess that `Add-MpPreference` may internally invoke does not appear
in Sysmon due to include-mode filtering, though it does appear in Security 4689 exit events.

## Assessment

The test succeeded. The exclusion for `C:\Temp` was added to Windows Defender's configuration.
The exit code 0x0 from MpCmdRun.exe in the exit log and the clean PowerShell exit confirm
successful execution. The large volume of Defender module parameter chunk events (28 fragments)
in the 4104 log is characteristic noise from the first-time module load; it provides no
detection value but correctly represents what defenders will observe in the wild.

## Detection Opportunities Present in This Data

- **PowerShell 4104 script block containing `Add-MpPreference -ExclusionPath`**: This is
  a high-fidelity indicator. There are few legitimate reasons to add Defender exclusions
  from an automated PowerShell script running as SYSTEM. The specific path `C:\Temp` is
  a common attacker staging location.

- **Security 4688 and Sysmon EID 1 command line**: The attack command is fully captured
  at process creation. Pattern matching on `Add-MpPreference` with `-ExclusionPath`,
  `-ExclusionExtension`, or `-ExclusionProcess` in PowerShell command lines is reliable.

- **Module load noise as context**: The presence of many 4104 events containing Defender
  module parameter definitions (recognizable by `ParameterSetName`, `ValidateNotNullOrEmpty`
  patterns) immediately following an `Add-MpPreference` invocation helps corroborate the
  attack and explains the volume spike in PowerShell logging.

- **Exclusion path value**: `C:\Temp` as an exclusion path is a commonly flagged indicator
  in threat intelligence. More broadly, any exclusion added to a temporary or user-writable
  directory warrants investigation.
