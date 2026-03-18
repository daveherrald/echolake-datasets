# T1553.006-1: Code Signing Policy Modification — Code Signing Policy Modification

## Technique Context

T1553.006 covers adversary modification of code signing policy to allow unsigned or improperly signed code to execute. On Windows, a primary mechanism is enabling test signing mode via `bcdedit /set testsigning on`, which instructs the kernel to accept drivers and executables signed with self-signed or test certificates. This is used by attackers who deploy custom kernel drivers or rootkits that cannot obtain a legitimate Microsoft-issued code signing certificate. The technique falls under Defense Evasion (TA0005) and typically appears as a precursor to driver-based persistence or rootkit deployment.

## What This Dataset Contains

The dataset spans approximately 5 seconds (2026-03-14T00:36:39Z – 00:36:44Z) and captures the execution of ART test T1553.006-1 on ACME-WS02, a Windows 11 Enterprise domain workstation in acme.local.

**The core attacker action is visible in the Security log (event 4688):**

> `"cmd.exe" /c bcdedit /set testsigning on`
> `bcdedit  /set testsigning on`

The call chain is: PowerShell (SYSTEM) → cmd.exe → bcdedit.exe. The Security log also records termination of bcdedit.exe with **exit code 0x1**, indicating failure rather than success. This is significant: on systems where Secure Boot is enforced, `bcdedit /set testsigning on` fails — producing attempt telemetry without completing the modification.

Sysmon (EID 1) records the same process chain with a rule tag of `technique_id=T1490,technique_name=Inhibit System Recovery`, reflecting the sysmon-modular config's classification of bcdedit as a recovery-inhibiting tool. Sysmon EID 7 (Image Loaded) records DLL loads into the parent PowerShell process: `AMSI.dll`, `clrjit.dll`, and related modules tagged under T1055 (Process Injection) and T1574.002 (DLL Side-Loading) by the sysmon-modular ruleset — these are normal module loads for PowerShell startup and are not injections.

The Security log includes a EID 4703 (Token Right Adjusted) showing that the PowerShell process had a broad privilege set enabled, including `SeLoadDriverPrivilege`, which is the privilege required to load kernel drivers — contextually relevant to the technique's objective.

PowerShell logs (EID 4103, 4104) are dominated by ART test framework boilerplate: `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`, and repetitive `Set-StrictMode`, error handler, and `OriginInfo` scriptblock fragments produced by the framework's internal pipeline mechanics. No scriptblock captures the `bcdedit` command directly, because it was executed via `cmd.exe` rather than a pure PowerShell cmdlet.

## What This Dataset Does Not Contain (and Why)

**Registry change confirming test signing was enabled.** Bcdedit modifies the BCD store (a firmware-level database), not a standard registry key. Object access auditing is not enabled in this environment, and Sysmon does not have a rule for BCD store modifications. The exit code 0x1 from bcdedit suggests the change was rejected — likely because Secure Boot is active on the Proxmox VM, which prevents test signing mode from being enabled from a running OS.

**Sysmon ProcessCreate for PowerShell or cmd.exe.** The sysmon-modular configuration uses include-mode filtering for EID 1. PowerShell and cmd.exe are only captured when specific rule patterns match. The security log (EID 4688) provides complementary full process creation coverage and is the primary source for the complete call chain here.

**Post-exploitation driver load.** The dataset represents only the attempt phase. If test signing had been successfully enabled and the system rebooted, a subsequent unsigned driver load would appear as Sysmon EID 6 (Driver Loaded). No such event is present.

## Assessment

This dataset captures a **failed attempt** to enable test signing mode. The key forensic artifact is the bcdedit command line in Security EID 4688 with an exit code of 0x1, demonstrating that the OS rejected the modification. The telemetry is forensically authentic: the call chain, privilege context, and token rights are consistent with a legitimate SYSTEM-level execution. The dataset does not include a Windows Defender block (no 0xC0000022 status code appears); bcdedit simply failed at the BCD layer rather than being prevented by Defender.

For defenders, this dataset illustrates that command-line telemetry alone is sufficient to detect this technique — no behavioral outcome (registry change, BCD modification) is required. The combination of Security 4688 and Sysmon EID 1 provides redundant coverage of the execution.

## Detection Opportunities Present in This Data

- **Security EID 4688**: Process creation for `bcdedit.exe` with command line containing `/set testsigning on`. High-fidelity indicator; bcdedit is rarely run legitimately outside of driver development environments.
- **Security EID 4689**: Exit status 0x1 for bcdedit.exe. Can be used to distinguish blocked vs. successful modification, though the attempt itself should alert regardless.
- **Security EID 4703**: Presence of `SeLoadDriverPrivilege` enabled in the PowerShell process context. Privilege enablement in a SYSTEM-context powershell session initiating bcdedit is an anomalous combination.
- **Sysmon EID 1**: bcdedit.exe process create with parent cmd.exe and grandparent powershell.exe — the process chain is directly observable, though this event is tagged with the T1490 rule rather than T1553.006 in the current sysmon-modular config.
- **PowerShell EID 4103**: `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` at session start — a consistent ART test framework artifact, useful for correlating scripted attack frameworks but present in all ART tests.
