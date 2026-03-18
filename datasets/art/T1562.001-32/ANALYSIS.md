# T1562.001-32: Disable or Modify Tools — cmd

## Technique Context

MITRE ATT&CK T1562.001 (Disable or Modify Tools) includes registry modifications that suppress or disable Windows security and privacy components. This test replicates a technique attributed to LockBit Black, which uses `reg.exe` to set `DisablePrivacyExperience` in the HKCU policy hive. The Privacy Settings Experience is the Windows Out-of-Box Experience (OOBE) privacy consent dialog. Suppressing it prevents users from reviewing or reverting privacy configurations that may include diagnostic data collection, telemetry, and other settings that could expose ransomware activity or impact persistence mechanisms. The `cmd.exe` variant (this test) invokes `reg.exe` directly from a batch-style command.

## What This Dataset Contains

The dataset captures 5 seconds of telemetry from ACME-WS02 during the cmd.exe-based registry modification test.

**Security 4688 — Full process chain from PowerShell to cmd.exe to reg.exe:**
```
"cmd.exe" /c reg add "HKCU\Software\Policies\Microsoft\Windows\OOBE" /v DisablePrivacyExperience /t REG_DWORD /d 1 /f
reg  add "HKCU\Software\Policies\Microsoft\Windows\OOBE" /v DisablePrivacyExperience /t REG_DWORD /d 1 /f
```
The double-space before `add` in the `reg.exe` command line is a characteristic artifact of how `cmd.exe` passes arguments when invoked via `/c`.

**Sysmon EID 1 — Process creates with parent-child chain:**
The full chain is visible: `powershell.exe` → `cmd.exe` → `reg.exe`. Both `WmiPrvSE.exe` (WMI provider host, ambient) and `whoami.exe` (ART identity check) also appear as EID 1 events.

**Sysmon EID 7 — Image loads:** Standard PowerShell runtime DLLs and Defender client libraries load into the test framework PowerShell process.

**Sysmon EID 10 — Process access:** Two events tagged `T1055.001` show the parent PowerShell opening handles to child processes with `GrantedAccess: 0x1FFFFF` (ART test framework overhead).

**PowerShell 4104 — Script block logging:** The test framework script block is present, though the attack itself executes via `cmd.exe` and does not generate additional interesting 4104 content.

**Security 4703 — Token right adjustments:** Privilege adjustments for the SYSTEM context. `WmiPrvSE.exe` spawning is an artifact of WMI activity unrelated to this test.

## What This Dataset Does Not Contain (and Why)

**Registry write confirmation via Sysmon EID 13** — Sysmon did not capture the registry modification. The `DisablePrivacyExperience` value is written to an HKCU policy path. The Sysmon-modular configuration includes rules for many registry paths, but this OOBE policy key may not be in the include list. The `reg.exe` exit status of `0x0` in Security 4689 confirms the write succeeded at the OS level.

**Any Defender alert or block** — Unlike the Backstab test, this registry modification was not blocked. The HKCU policy hive is not a protected area and does not require elevated privilege to modify.

**Script block content for the `reg add` command** — The registry modification was executed via `cmd.exe`, not PowerShell, so PowerShell 4104 does not contain the `reg add` command text. The Security 4688 command line is the primary source for the command-line evidence.

**Object access auditing** — The audit policy on this host has `object_access: none`, so no EID 4656/4663 events for registry key access appear.

## Assessment

This is a **successful execution** dataset. Both `cmd.exe` and `reg.exe` exited with status `0x0`, indicating the registry value was written. The process creation chain (`powershell.exe` → `cmd.exe` → `reg.exe`) is well-documented across Security 4688 and Sysmon EID 1. The `cmd.exe /c reg add` invocation pattern is a common pattern in many attacker toolkits. The double-space artifact in `reg  add` (two spaces) is a minor but potentially useful fingerprint for correlation. The dataset illustrates a simple, low-noise attack with a compact but complete telemetry trail covering process creation, command line, and exit status.

## Detection Opportunities Present in This Data

- **`reg.exe` modifying OOBE policy key** (Security 4688 / Sysmon EID 1): `reg add "HKCU\Software\Policies\Microsoft\Windows\OOBE" /v DisablePrivacyExperience` is a specific, low-prevalence command. Even with only process creation logging, this command line is deterministic.
- **`powershell.exe` → `cmd.exe` → `reg.exe` process chain**: The three-hop chain from a PowerShell parent to cmd.exe to reg.exe for registry modification is a well-known detection pattern. Correlating process creation parent-child relationships adds confidence.
- **Sysmon EID 1 with `reg.exe` and HKCU policy path**: Even without Security 4688, Sysmon captures the `reg.exe` command line in include-mode because `reg.exe` is in the sysmon-modular suspicious process list.
- **Registry key path** (if registry auditing enabled): `HKCU\Software\Policies\Microsoft\Windows\OOBE\DisablePrivacyExperience` is a specific LockBit-associated IoC when written with value `1`.
