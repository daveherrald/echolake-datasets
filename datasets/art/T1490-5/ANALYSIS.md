# T1490-5: Inhibit System Recovery — Delete Volume Shadow Copies via WMI with PowerShell

## Technique Context

MITRE ATT&CK T1490 (Inhibit System Recovery) covers multiple paths to VSC deletion. This test exercises the PowerShell WMI interface — `Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}` — which is a common ransomware variant that avoids the more-signatured `vssadmin delete shadows` and `wmic shadowcopy delete` command strings. This pattern has appeared in Ryuk, WastedLocker, and various Cobalt Strike post-exploitation frameworks. It deletes shadow copies through a COM/WMI method call rather than via a subprocess, which means some process-creation-only detections will not fire. The technique relies on the `Win32_ShadowCopy` WMI class's `Delete()` method, callable from any language that can invoke WMI.

## What This Dataset Contains

**Sysmon (Event ID 1) — ProcessCreate:**
The test framework runs PowerShell with the command line: `"powershell.exe" & {Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}}`. This is captured by Sysmon's include-mode filter because PowerShell itself matches the T1059.001 rule. Separately, `WmiPrvSE.exe` (WMI Provider Host) is also captured as a Sysmon EID 1 event, tagged `technique_id=T1047,technique_name=Windows Management Instrumentation` — this is the WMI provider process that actually services the `Win32_ShadowCopy::Delete()` call. Both are running as different users: PowerShell under SYSTEM, WmiPrvSE under `NT AUTHORITY\NETWORK SERVICE`.

**Sysmon (Event ID 3) — NetworkConnect:**
Four outbound TCP connections from `MsMpEng.exe` (Windows Defender) to `48.211.71.202:443` are captured during the execution window. These are Defender cloud telemetry connections triggered when the suspicious WMI call was inspected. This is authentic background activity you would see in production. Two mDNS (UDP/5353) events from `svchost.exe` are also present — unrelated OS traffic.

**Security (Event IDs 4624/4627/4672/4688/4689/4703):**
The security log includes WmiPrvSE.exe process creation (logged under the NETWORK SERVICE context), the PowerShell process chain, and logon events (4624 type 5, 4627, 4672) for the WMI service account activation — the same service-spawn pattern seen in T1490-3. The PowerShell process exits with `0x0`.

**PowerShell (Event ID 4104) — Script Block Logging:**
Two script block entries capture the actual WMI delete code:
- `& {Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}}`
- `{Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}}`

**PowerShell (Event ID 4103) — Module Logging:**
`CommandInvocation(Get-WmiObject)` with `ParameterBinding(Get-WmiObject): name="Class"; value="Win32_Shadowcopy"` and `CommandInvocation(ForEach-Object)` with `ParameterBinding(ForEach-Object): name="Process"; value="$_.Delete();"` are logged. This is uniquely valuable: it surfaces the exact WMI class and method even when the command line is obfuscated.

## What This Dataset Does Not Contain

- **WMI Activity channel events.** The `Microsoft-Windows-WMI-Activity/Operational` channel is not bundled. In a real detection deployment you would expect WMI 5857/5860/5861 events showing the `Win32_ShadowCopy` query and method invocation.
- **VSS Application log confirmation** (e.g., EID 524) that shadow copies were actually deleted. Because this is a workstation with no configured backup, the `Delete()` call may have found no shadow copies to remove.
- **No Sysmon EID 20 (WmiEvent)** — Sysmon's WMI event consumer/filter logging is not triggered by this method call pattern.

## Assessment

This is one of the strongest datasets in the T1490 collection for the PowerShell/WMI deletion variant. The combination of Sysmon EID 1 (WmiPrvSE.exe spawn with T1047 tag), PowerShell EID 4104 script block (exact WMI delete code), and PowerShell EID 4103 module logging (explicit class/method binding) gives detection engineers three independent sources to write against. The Defender network telemetry to `48.211.71.202:443` is authentic production noise that confirms this is a live, instrumented environment. Adding the WMI Activity channel would complete the picture.

## Detection Opportunities Present in This Data

1. **PowerShell EID 4104 — script block containing `Win32_Shadowcopy` and `Delete()`** — captures the exact WMI delete call independent of command-line obfuscation.
2. **PowerShell EID 4103 — `Get-WmiObject` invocation with `Class=Win32_Shadowcopy`** — module logging surfaces the WMI class name even when the script uses aliases or variable substitution.
3. **Sysmon EID 1 — `WmiPrvSE.exe` spawned as NETWORK SERVICE** in temporal proximity to a `powershell.exe` process executing WMI — the parent/timing correlation indicates a WMI method call serviced by the provider host.
4. **Security EID 4688 — `powershell.exe` command line containing `Win32_Shadowcopy`** — command-line auditing captures the argument even when Sysmon's ProcessCreate filter is absent.
5. **Security EID 4624/4672 — service logon for WmiPrvSE** immediately following the PowerShell launch — the authentication side effect of the WMI provider activation.
6. **Sysmon EID 1 — PowerShell launched from `C:\Windows\TEMP\` as SYSTEM** — the directory and account context are anomalous for legitimate PowerShell use.
