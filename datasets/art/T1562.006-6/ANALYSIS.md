# T1562.006-6: Indicator Blocking — cmd

## Technique Context

MITRE ATT&CK T1562.006 (Indicator Blocking) includes suppressing the .NET CLR's ETW
instrumentation. The `HKLM\Software\Microsoft\.NETFramework\ETWEnabled` registry value,
when set to `0`, instructs the .NET runtime to skip ETW instrumentation across all processes
loading the CLR. Adversaries use this before executing .NET-based tools (Cobalt Strike
Beacon, offensive C# tooling) to prevent defenders from observing method-level tracing,
JIT events, and garbage collection telemetry that can reveal in-memory .NET payloads.

This test uses `cmd.exe` and `reg.exe` — the lowest-tech approach — to write the value.

## What This Dataset Contains

The test executes a straightforward registry write:

```
cmd.exe /c REG ADD HKLM\Software\Microsoft\.NETFramework /v ETWEnabled /t REG_DWORD /d 0
```

Security EID 4688 captures the full chain: `powershell.exe` spawns `cmd.exe` which spawns
`reg.exe` with the complete command line. Sysmon EID 1 duplicates this with parent process
annotations. Sysmon EID 13 (RegistryValueSet) records the actual write:

```
TargetObject: HKLM\SOFTWARE\Microsoft\.NETFramework\ETWEnabled
Details: DWORD (0x00000000)
Image: C:\Windows\system32\reg.exe
```

This is the most precise single event for detection: the target path, value, and writing
process are all present.

## What This Dataset Does Not Contain (and Why)

No Sysmon EID 12 (RegistryKeyCreate) appears because the `.NETFramework` key already exists;
only the value write (EID 13) fires. No network or DNS events are present. The audit policy
does not include Object Access, so there are no Security log registry audit events — EID 4657
is absent. The PowerShell Operational events are dominated by ART test framework boilerplate (EID
4104 fragments for error handlers and `Set-StrictMode`); no PowerShell-native registry cmdlets
were used in this test variant (compare with T1562.006-7 which uses `New-ItemProperty`).

## Assessment

The test completed successfully; the registry value write is confirmed by Sysmon EID 13. The
Security EID 4688 chain provides process lineage from the ART test framework through `cmd.exe` to
`reg.exe`. Detection is straightforward because `reg.exe` writing
`HKLM\Software\Microsoft\.NETFramework\ETWEnabled` to `0` is a highly specific indicator
with essentially no legitimate use in a production Windows environment.

The PowerShell boilerplate blocks are test framework artifacts from the ART execution wrapper
and do not represent additional attacker activity.

## Detection Opportunities Present in This Data

- **Sysmon EID 13**: `TargetObject` matching `HKLM\SOFTWARE\Microsoft\.NETFramework\ETWEnabled`
  with `Details: DWORD (0x00000000)` — this is a near-zero false-positive signature.
- **Security EID 4688**: `reg.exe` command line containing `\.NETFramework` and `/v ETWEnabled`
  and `/d 0`.
- **Sysmon EID 1**: Same `reg.exe` invocation with parent process chain showing unusual spawn
  origin (`powershell.exe` → `cmd.exe` → `reg.exe`).
- **Pattern**: `cmd.exe` spawning `reg.exe` with the `HKLM\Software\Microsoft\.NETFramework`
  path is unusual and not associated with any common administrative workflow.
