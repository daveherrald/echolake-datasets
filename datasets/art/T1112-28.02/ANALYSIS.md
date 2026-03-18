# T1112-28: Modify Registry — Windows HideSCAHealth Group Policy Feature

## Technique Context

The `HideSCAHealth` registry value (`HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` set to `1`) hides the Windows Security Center (Action Center) health notification area icon and its associated status indicators. Windows Security Center aggregates warnings about antivirus status, firewall configuration, Windows Update, and other security posture components into a single notification icon in the taskbar. Setting `HideSCAHealth` to `1` removes this icon and suppresses its status warnings from the user's view.

This is the most security-relevant modification in the T1112 Explorer policy series. Unlike HideClock (which hides a clock) or NoFileMenu (which removes a file menu), HideSCAHealth specifically targets the user's visibility into the security state of their machine. An attacker who has already disabled Windows Defender (which generates a Security Center warning) could also hide the Security Center icon to prevent the user from seeing the warning. This makes HideSCAHealth a logical complement to defense evasion techniques rather than a standalone restriction.

The execution pattern follows the identical structure used throughout this series. As in T1112-27, this dataset contains ART test framework timing artifacts in the PowerShell EID 4104 stream that expose the test framework's internal timing mechanism.

## What This Dataset Contains

This dataset captures 69 events across three channels (48 PowerShell, 4 Security, 17 Sysmon) collected over a 5-second window (2026-03-14T23:49:56Z–23:50:01Z) on ACME-WS06 with Defender disabled.

**Process Creation Chain (Security EID 4688):**

Four EID 4688 events document the complete execution:
1. `whoami.exe` — pre-test identity check
2. `cmd.exe` with command: `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAHealth /t REG_DWORD /d 1 /f`
3. `reg.exe` with command: `reg  add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAHealth /t REG_DWORD /d 1 /f`
4. `whoami.exe` — post-test identity check

**Sysmon Process Creates (EID 1):**

Four EID 1 events with complete process ancestry and hash data:
- `whoami.exe` (PID 1272): parent GUID `{9dc7570a-f422-69b5-d811-000000000600}` (parent PowerShell PID 7072), tagged `T1033`
- `cmd.exe` (PID 5540): full HideSCAHealth command, SHA256 `423E0E810A69AACEBA0E5670E58AFF898CF0EBFFAB99CCB46EBB3464C3D2FACB`, IMPHASH `D73E39DAB3C8B57AA408073D01254964`, tagged `T1059.003`
- `reg.exe` (PID 7136): full reg add command, SHA256 `411AE446FE37B30C0727888C7FA5E88994A46DAFD41AA5B3B06C9E884549AFDE`, IMPHASH `1085BD82B37A225F6D356012D2E69C3D`, parent GUID `{9dc7570a-f428-69b5-dd11-000000000600}` (cmd.exe), tagged `T1012`
- Fourth process create from cleanup phase

The process chain: PowerShell (PID 7072) → cmd.exe (PID 5540) → reg.exe (PID 7136). The parent GUID cross-links are consistent, confirming the complete ancestry.

**Sysmon Image Loads (EID 7):**

9 EID 7 events for .NET CLR DLL loads on the parent PowerShell (PID 7072): the standard `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `System.Management.Automation.ni.dll` sequence.

**Sysmon Process Access (EID 10):**

3 EID 10 events showing the parent PowerShell accessing child processes with `GrantedAccess: 0x1FFFFF`.

**Sysmon Named Pipe Create (EID 17):**

One EID 17 event for the standard PowerShell host pipe.

**PowerShell Script Block Logging (EID 4104):**

48 EID 4104 events. Among the standard runtime boilerplate, two substantive ART test framework script blocks appear:
- `$startEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()` — marks the start of the test execution
- `$endEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()` — marks the end

These timing artifacts are characteristic of ART test execution and indicate that this was a timed test run. They are not malicious but serve as reliable markers for identifying ART-framework-generated events.

## What This Dataset Does Not Contain

- **Sysmon EID 13 for the HideSCAHealth registry write:** The Sysmon configuration does not monitor `HKCU\...\Policies\Explorer` for SetValue events. Only the process chain provides evidence of the modification.
- **Security Center status change events:** No Windows event records the SCA notification icon being hidden.
- **The effect of HideSCAHealth in combination with disabled Defender:** With Defender disabled on this test system, Security Center would normally display a persistent warning. HideSCAHealth would suppress that warning from the taskbar. No event captures this combined state.
- **Network activity:** No network connections are involved in this technique.

## Assessment

HideSCAHealth is the most operationally motivated modification in the T1112 Explorer policy series. While hiding the taskbar clock or file menu are minor annoyances, hiding the Security Center icon directly addresses a visible indicator that Defender is disabled. An attacker who disabled Defender (or another security product) would rationally follow up with HideSCAHealth to prevent the victim from seeing the resulting warning.

The dataset itself is compact (69 events) and forensically straightforward: Security EID 4688 and Sysmon EID 1 provide the complete process chain with command lines and hashes. The ART timing artifacts (`$startEpoch`, `$endEpoch`) in the EID 4104 stream are consistent markers of the ART test framework.

Compared to the defended variant (84 events: 35 PowerShell, 12 Security, 37 Sysmon), the undefended version (69 events) is smaller, reflecting differences in ambient background events during each test run. The Sysmon count (17 vs. 37) and Security count (4 vs. 12) differences follow the same pattern as the rest of the series: Defender's background processes generate additional events in the defended variant.

## Detection Opportunities Present in This Data

**EID 4688 / Sysmon EID 1 — HideSCAHealth in reg add Command:**
The `reg add` targeting `HKCU\...\Policies\Explorer` with value `HideSCAHealth` is a high-value indicator given its direct relationship to suppressing Security Center warnings. This specific value name, in combination with the Explorer Policies path, provides high-confidence attribution to defense evasion intent.

**Behavioral Correlation — HideSCAHealth Following Security Product Modification:**
In a real environment, HideSCAHealth appearing shortly after a Defender disable event (e.g., registry modification to `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware`) would be a strong indicator of a coordinated defense evasion sequence. The temporal correlation between these two registry modification types is a meaningful behavioral pattern.

**Sysmon EID 1 — ART Timing Artifacts ($startEpoch / $endEpoch):**
The `$startEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()` script blocks in EID 4104 are specific to the ART test framework. In a production environment, these script blocks appearing in PowerShell logging indicate ART framework execution, which is useful for identifying test environments vs. genuine attack traffic.

**reg.exe IMPHASH Consistency:**
The reg.exe IMPHASH `1085BD82B37A225F6D356012D2E69C3D` is consistent across all T1112 tests in this series (T1112-19, T1112-21, T1112-22, T1112-24, T1112-27, T1112-28, T1112-30). This provides a stable hash baseline for the reg.exe binary on Windows 11 22H2 build 22631, suitable for building a known-good hash allowlist or detecting replaced binaries.
