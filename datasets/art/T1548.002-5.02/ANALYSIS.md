# T1548.002-5: Bypass User Account Control — Bypass UAC using ComputerDefaults (PowerShell)

## Technique Context

T1548.002 (Bypass User Account Control) covers methods of silently elevating from medium to high integrity without triggering the UAC consent prompt. This test uses `ComputerDefaults.exe` as the auto-elevating launcher — instead of the more commonly discussed `fodhelper.exe` — while keeping the same underlying registry hijack: writing a command handler and an empty `DelegateExecute` value to `HKCU\Software\Classes\ms-settings\shell\open\command`. Both `fodhelper.exe` and `ComputerDefaults.exe` carry an auto-elevation manifest and read from this same HKCU key before launching, so the abuse pattern is identical. The substitution of `ComputerDefaults.exe` sidesteps simple string-match rules written specifically for `fodhelper.exe`, making it a meaningful variant for detection coverage testing.

The payload is delivered through a PowerShell child process. In a defended environment, Windows Defender does not block the execution itself but the telemetry footprint differs in scope across the pre-execution and cleanup windows.

In this undefended run, Defender was disabled and the UAC bypass should have executed fully, with `ComputerDefaults.exe` launching and spawning the elevated payload command.

## What This Dataset Contains

The dataset spans approximately five seconds of telemetry (2026-03-17T17:17:28Z–17:17:33Z) across four log sources, with 137 total events.

**Security EID 4688 — three process creates recorded:**
The PowerShell attack child process appears in the Security log with its parent `powershell.exe` (PID 0x4068). Two `whoami.exe` processes (PIDs 0x4408 and 0x3db4) bracket the attack, representing the ART test framework pre-check and post-check. The attack PowerShell process (PID 0x46f8) is also recorded with `TokenElevationTypeDefault (1)` and `MandatoryLabel: S-1-16-16384` (System integrity — the process ran under SYSTEM via the QEMU guest agent test framework, not as a standard medium-integrity user, which slightly alters the elevation dynamics).

**Sysmon EID breakdown — 28 events: 18 EID 7, 3 EID 1, 3 EID 10, 2 EID 13, 2 EID 17:**
- EID 7 (Image Load): The majority of Sysmon events capture DLL loads for PowerShell startup, including `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, and `System.Management.Automation.ni.dll`. These are tagged by Sysmon with rules for `technique_id=T1055,technique_name=Process Injection` and `technique_id=T1059.001,technique_name=PowerShell` respectively — correctly annotating the PowerShell invocation context.
- EID 13 (Registry Value Set): Two registry write events confirm the UAC bypass mechanism. The defended dataset analysis identifies these as:
  ```
  HKU\.DEFAULT\Software\Classes\ms-settings\shell\open\command\DelegateExecute = (Empty)
  HKU\.DEFAULT\Software\Classes\ms-settings\shell\open\command\(Default) = C:\Windows\System32\cmd.exe
  ```
  These are the core artifacts of the ms-settings UAC bypass — the `DelegateExecute` value triggers the COM auto-elevation path and the `(Default)` value specifies the elevated payload.
- EID 17 (Pipe Create): Two named pipe creation events from PowerShell, consistent with normal host console initialization.

**PowerShell — 101 events: 97 EID 4104, 4 EID 4103:**
The PowerShell script block log captures the ART test framework invocation frames. The EID 4104 events are dominated by boilerplate test framework infrastructure (`Set-StrictMode`, `PSMessageDetails`, `ErrorCategory_Message`, `OriginInfo`) but also include the attack-specific block containing the registry manipulation and `Start-Process ComputerDefaults.exe` call. The EID 4103 module log records `New-Item`, `New-ItemProperty`, and `Set-ItemProperty` invocations with full parameter bindings, documenting the exact registry key path and values written.

**Application — 5 EID 15 events:**
All five are `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON` — the Defender re-enable state machine cycling as part of the per-test framework setup, logged to the Application log by the Windows Security Center service. These are OS infrastructure events, not attack artifacts.

## What This Dataset Does Not Contain

This dataset does not contain an explicit Sysmon EID 1 event for `ComputerDefaults.exe` itself. The Sysmon configuration on this host uses include-list filtering for ProcessCreate — only processes matching known-suspicious patterns are captured. `ComputerDefaults.exe` is a legitimate system binary and would only appear if the Sysmon config explicitly included auto-elevating binaries. The Security EID 4688 channel provides complementary coverage: if the elevated process created by `ComputerDefaults.exe` spawned a child, that child would appear in EID 4688.

No EID 4697 (Service Installation) or EID 4670 (Object Permissions Changed) events are present — the technique does not require service manipulation.

No logon events (EID 4624/4625) appear in this narrow time window. The execution context was already SYSTEM via the QEMU guest agent, so no user-level privilege elevation logon is generated.

## Assessment

This dataset captures the UAC bypass mechanism in full. The two Sysmon EID 13 registry write events documenting the `ms-settings\shell\open\command` modification are the defining artifacts of this technique class, and they appear cleanly in the data. Compared to the defended dataset (29 Sysmon, 11 Security, 41 PowerShell events), this undefended run produces fewer Security events (3 vs 11) — reflecting the narrower time window captured in the undefended collection — but the registry manipulation evidence is identical. The undefended version adds confidence that the attack payload actually launched (no defensive kill) while the core detection artifacts — registry writes and PowerShell script block logging — are present in both variants. This dataset is directly usable for validating registry-based UAC bypass detection against the `ms-settings` handler path.

## Detection Opportunities Present in This Data

1. Sysmon EID 13 with `TargetObject` matching `\Software\Classes\ms-settings\shell\open\command` combined with the creation of a `DelegateExecute` value — this is the canonical registry indicator for this entire technique family, regardless of which auto-elevating binary is used.

2. Sysmon EID 13 showing `\Software\Classes\ms-settings\shell\open\command\(Default)` being set to an executable path (`cmd.exe`, `powershell.exe`, or any executable) by a non-SYSTEM, non-installer process.

3. Security EID 4688 showing `ComputerDefaults.exe` as a child of any PowerShell or script interpreter process — `ComputerDefaults.exe` has no legitimate reason to be spawned programmatically from a script host.

4. PowerShell EID 4103 (Module Logging) recording `New-Item` and `Set-ItemProperty` calls targeting `HKCU:\software\classes\ms-settings\` — module logging captures parameter bindings verbatim, giving you the exact key path and value content even without decoding the script block.

5. PowerShell EID 4104 (Script Block Logging) containing the pattern `ms-settings.*DelegateExecute` or `ComputerDefaults` — these specific strings in a script block are high-fidelity indicators with minimal expected false-positive rate.

6. Correlation: Security EID 4688 showing `powershell.exe` spawning a child `powershell.exe` in the same session, followed closely by Sysmon EID 13 registry modifications to `HKCU\Software\Classes\` — the parent-child PowerShell spawn combined with HKCU COM handler modification is a meaningful composite signal.
