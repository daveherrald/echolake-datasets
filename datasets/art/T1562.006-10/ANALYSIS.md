# T1562.006-10: Indicator Blocking — Disable .NET ETW via Environment Variable HKCU Registry - Cmd

## Technique Context

T1562.006 (Indicator Blocking) covers techniques that prevent security tools from collecting
telemetry. Setting `COMPlus_ETWEnabled=0` in the Windows registry disables Event Tracing for
Windows (ETW) for .NET CLR processes that load with that environment variable in scope. When set
in `HKCU\Environment`, it affects .NET applications running under the current user. This is a
well-known .NET ETW bypass used to blind tools like ScriptBlock Logging, AMSI-over-ETW, and
any ETW-based .NET monitoring (Elastic, Microsoft Defender for Endpoint, etc.) for .NET processes
spawned in that user context.

This test uses `cmd.exe` with `reg.exe` to write the value:
`REG ADD HKCU\Environment /v COMPlus_ETWEnabled /t REG_SZ /d 0 /f`

## What This Dataset Contains

**Sysmon EID 1 — process creation (28 events, 3 process-create):**
- `cmd.exe /c REG ADD HKCU\Environment /v COMPlus_ETWEnabled /t REG_SZ /d 0 /f` (parent: powershell.exe, under WmiPrvSE.exe)
- `reg.exe REG ADD HKCU\Environment /v COMPlus_ETWEnabled /t REG_SZ /d 0 /f` (child of cmd.exe)
- `whoami.exe`

**Sysmon EID 13 — registry value set (1 event):**
```
TargetObject: HKU\.DEFAULT\Environment\COMPlus_ETWEnabled
Details: 0
Image: C:\Windows\system32\reg.exe
User: NT AUTHORITY\SYSTEM
```
Note: Because the test runs as SYSTEM, `HKCU` resolves to `HKU\.DEFAULT` rather than a
user-specific hive. In a real attack running as a regular user, this would appear under
`HKU\<user-SID>\Environment\COMPlus_ETWEnabled`.

**Security EID 4688 (12 events):** whoami.exe, cmd.exe, reg.exe. All SYSTEM context.

**PowerShell EID 4104 (34 events):** ART test framework boilerplate only. The reg.exe command was
invoked via cmd.exe; no test-specific content appears in script block logging.

## What This Dataset Does Not Contain (and Why)

**No EID 4657 (registry value modification) in Security log:** Auditing of registry object access
requires enabling `object_access` in the audit policy, which is set to `none` in this environment.
Registry changes are captured only via Sysmon EID 13.

**No ETW provider disable events:** Windows does not generate a dedicated event when ETW is
suppressed via environment variable. The change takes effect when the next .NET process starts;
there is no runtime notification in the event log.

**No .NET CLR process behavior change in this capture:** The value is written but no .NET
application is subsequently launched during the test window, so there is no observable effect on
downstream logging.

## Assessment

The dataset is concise and the indicator is clear. The single Sysmon EID 13 event writing
`HKU\.DEFAULT\Environment\COMPlus_ETWEnabled = 0` by reg.exe is the core detection artifact.
The full reg.exe command line in Sysmon EID 1 (`REG ADD HKCU\Environment /v COMPlus_ETWEnabled
/t REG_SZ /d 0 /f`) is equally actionable. The process chain
`powershell.exe -> cmd.exe -> reg.exe` with this specific registry target is highly anomalous
on enterprise workstations. Test executed successfully.

Because the test ran as SYSTEM, the registry path shows `HKU\.DEFAULT` rather than a user SID.
Detection rules should cover both `HKU\.DEFAULT\Environment\COMPlus_ETWEnabled` and
`HKU\*\Environment\COMPlus_ETWEnabled` to catch both SYSTEM-context and user-context attacks.

## Detection Opportunities Present in This Data

- **Sysmon EID 13:** `TargetObject` matching `*\Environment\COMPlus_ETWEnabled` with `Details: 0` — direct, high-confidence indicator regardless of the hive (HKCU, HKU\*)
- **Sysmon EID 1:** `reg.exe` with command line containing `COMPlus_ETWEnabled` and `/d 0`
- **Sysmon EID 1:** `cmd.exe` spawned from `powershell.exe` under SYSTEM where the command line contains `COMPlus_ETWEnabled`
- **Security EID 4688:** `reg.exe` process creation with command-line logging showing `COMPlus_ETWEnabled` and `REG_SZ` `0`
- **Hive coverage:** Monitor both `HKCU\Environment` (user-context attacks) and `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment` (system-wide attacks) for this value
