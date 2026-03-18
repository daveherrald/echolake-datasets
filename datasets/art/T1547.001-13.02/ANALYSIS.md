# T1547.001-13: Registry Run Keys / Startup Folder — HKLM Policy Settings Explorer Run Key

## Technique Context

T1547.001 covers Registry Run Keys and Startup Folder persistence. This test exercises the machine-wide counterpart to T1547.001-12: the Group Policy-administered Run key at `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`. Unlike the HKCU variant, this HKLM path applies to all users on the system — executables registered here run at logon for every user, not just the current one. Writing to HKLM requires administrative privileges, restricting this variant to attackers who have already elevated.

The `Policies\Explorer\Run` path in HKLM is functionally equivalent to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` for execution purposes, but occupies a different registry subtree that many monitoring tools treat differently. The `Policies\` subtree is associated with Group Policy configuration, making writes to it less likely to trigger alerts in environments where GPO software deployment is configured. This is the same evasion rationale as the HKCU variant in T1547.001-12.

The test conditionally creates `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` if it does not exist, then writes a value `atomictest` pointing to `C:\Windows\System32\calc.exe`.

In the defended variant, this test produced 43 Sysmon events (vs 27 here). As with T1547.001-12, the 16-event gap reflects Defender's monitoring overhead adding DLL load and process access events without blocking the technique.

## What This Dataset Contains

The dataset spans 4 seconds (2026-03-17 17:09:24–17:09:28 UTC) on ACME-WS06 (`acme.local`), executing as `NT AUTHORITY\SYSTEM`.

**Sysmon (27 events — Event IDs 1, 7, 10, 11, 13, 17):**

Sysmon EID 1 (ProcessCreate, 3 events):

1. `whoami.exe` — test framework context check, tagged `technique_id=T1033`
2. `powershell.exe` — tagged `technique_id=T1083`, full command line:
   ```
   "powershell.exe" & {if (!(Test-Path -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\")){
     New-Item -ItemType Key -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\"
   }
   Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -Name "atomictest" -Value "C:\Windows\System32\calc.exe"}
   ```
3. `whoami.exe` — second context check

Sysmon EID 13 (RegistrySetValue, 1 event) tagged `technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder`:
- `TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\atomictest`
- `Details: C:\Windows\System32\calc.exe`
- Set by `powershell.exe` (PID 17256) as `NT AUTHORITY\SYSTEM`

This is the persistence artifact. Unlike the HKCU variant (T1547.001-12), where the TargetObject uses the `HKU\.DEFAULT\` prefix, this HKLM write is recorded with the `HKLM\` prefix directly. The value name `atomictest` and payload path `C:\Windows\System32\calc.exe` match T1547.001-12 exactly, illustrating that the same ART test script applies to both hives.

Sysmon EID 11 (FileCreate, 1 event) records the PowerShell startup profile data file. Sysmon EID 7 (ImageLoad, 17 events), EID 10 (ProcessAccess, 3 events), and EID 17 (PipeCreate, 2 events) are standard PowerShell initialization artifacts.

**Security (3 events — Event ID 4688):**

Three process creation events: `whoami.exe`, `powershell.exe` (full command line), and a second `whoami.exe`. Identical structure to T1547.001-12 in the Security channel.

**PowerShell (101 events — Event IDs 4103, 4104):**

ScriptBlock logging captures the test payload and cleanup. The cleanup script removes the `atomictest` value via `Remove-ItemProperty`. One fewer PowerShell EID 4104 event than T1547.001-12 (101 vs 102), consistent with T1547.001-13 having one fewer `New-Item` call (the `Explorer` key creation is skipped because it already exists from the T1547.001-12 run immediately preceding this test).

## What This Dataset Does Not Contain

- **No logon execution:** `calc.exe` is registered under `Policies\Explorer\Run` but is not executed during the test window — no user logon occurred.
- **No HKLM key creation events:** The `New-Item` for `HKLM\...\Policies\Explorer\Run` would generate a Sysmon EID 12 event, but it is not present in the available samples.
- **Cleanup removes the artifact:** The `atomictest` value is removed by the cleanup script. No EID 13 deletion event is captured.
- **System-wide scope not exercised:** The HKLM variant affects all users, but since no logon occurs during the test, the broader impact relative to the HKCU variant is not demonstrated in the telemetry.

## Assessment

T1547.001-12 and T1547.001-13 are structurally nearly identical datasets. Both produce 27 Sysmon events in the undefended configuration, both have Sysmon EID 13 capturing the Run key write, and both have minimal Security and PowerShell channel differentiation. The key difference is the hive: `HKU\.DEFAULT\` vs `HKLM\` in the EID 13 `TargetObject` field. This difference has significant real-world impact — HKLM affects all users and requires admin privileges — but is represented in the telemetry only as a path prefix difference in a single EID 13 field.

The defended variants differ more substantially (43 vs 47 Sysmon events respectively), with T1547.001-12 generating slightly more Defender overhead — possibly because the HKCU hive write triggers different Defender scanning behavior than the HKLM write.

## Detection Opportunities Present in This Data

- **Sysmon EID 13:** `TargetObject` matching `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\*` with any value pointing to an executable. Writes to `HKLM\...\Policies\Explorer\Run` are specifically associated with GPO software deployment; a value added by `powershell.exe` or any non-GPO-infrastructure process is anomalous.
- **Sysmon EID 1 / Security EID 4688:** `powershell.exe` command line containing `Set-ItemProperty` targeting `HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`. The HKLM form requires elevation; finding this pattern in a non-administrative context would indicate privilege escalation.
- **PowerShell EID 4104:** `Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -Name "atomictest" -Value "..."` in a ScriptBlock. The HKLM path variant is a stronger indicator than the HKCU variant because legitimate user-space tooling does not write to `HKLM\...\Policies\Explorer\Run`.
- **Comparative to T1547.001-12:** If both HKCU and HKLM `Policies\Explorer\Run` entries appear in sequence from the same host in a short time window, the combination is a strong indicator of systematic persistence setup — one for the current session and one for all users.
