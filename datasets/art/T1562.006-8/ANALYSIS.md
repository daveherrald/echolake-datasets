# T1562.006-8: Indicator Blocking — cmd

## Technique Context

MITRE ATT&CK T1562.006 (Indicator Blocking) covers actions that prevent security tools from
generating telemetry. This test emulates behavior documented in the LockBit Black (LockBit 3.0)
ransomware: disabling the Windows Defender ETW event log channel by setting the `Enabled`
registry value to `0` under the Windows Defender Operational channel key. When this channel
is disabled, Windows Defender stops writing operational events — including detections,
scan results, and threat actions — to the event log, reducing forensic visibility during
and after an attack.

This test uses `cmd.exe` and `reg.exe` to perform the write, the same approach attributed
to LockBit Black's pre-ransomware preparation phase.

## What This Dataset Contains

The test executes:

```
cmd.exe /c reg add
  "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\
   Microsoft-Windows-Windows Defender/Operational"
  /v Enabled /t REG_DWORD /d 0 /f
```

Security EID 4688 records the process chain: `powershell.exe` spawns `cmd.exe` which spawns
`reg.exe` with the complete channel path and `/d 0 /f` (set to 0, force overwrite) arguments.
Sysmon EID 1 captures the same chain with parent process annotation. Sysmon EID 13
(RegistryValueSet) records the actual write:

```
TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\
              Microsoft-Windows-Windows Defender/Operational\Enabled
Details: DWORD (0x00000000)
Image: C:\Windows\system32\reg.exe
```

## What This Dataset Does Not Contain (and Why)

No Windows Defender detection events appear for this specific registry write — Defender's
behavior monitoring did not flag disabling its own log channel via `reg.exe`. No network
events are present. Object Access auditing is not enabled (Security EID 4657 absent).
No Sysmon EID 12 fires because the channel key already exists and only the value is modified.

Notably absent: any Windows Event Log service events (EID 6, EID 105 in
Microsoft-Windows-Eventlog) reflecting the channel being disabled. Capturing such events
would require collecting the System channel, which is not part of this dataset.

## Assessment

The test completed successfully; Sysmon EID 13 confirms the write. The combination of the
registry path (`WINEVT\Channels\Microsoft-Windows-Windows Defender/Operational\Enabled`)
and value `0` written by `reg.exe` is a high-confidence LockBit Black indicator that also
overlaps with other ransomware families performing pre-encryption cleanup. The process chain
from `powershell.exe` through `cmd.exe` to `reg.exe` is consistent with other T1562.006
tests in this series, providing a common detection pattern across variants 6, 7, 8, and 9.

## Detection Opportunities Present in This Data

- **Sysmon EID 13**: `TargetObject` containing `WINEVT\Channels\Microsoft-Windows-Windows
  Defender/Operational\Enabled` with `Details: DWORD (0x00000000)`.
- **Security EID 4688**: `reg.exe` command line containing the Defender Operational channel
  path and `/d 0`.
- **Sysmon EID 1**: `reg.exe` spawn with parent `cmd.exe`, grandparent `powershell.exe`, and
  full command line including the Defender ETW channel path.
- **Cross-source correlation**: Matching EID 4688 (Security) with EID 13 (Sysmon) on the
  same timestamp window confirms both the process and the resulting registry state change.
