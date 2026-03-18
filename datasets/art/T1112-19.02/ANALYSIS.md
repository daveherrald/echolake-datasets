# T1112-19: Modify Registry — Activate Windows NoRun Group Policy Feature

## Technique Context

Registry modification (T1112) is one of the most broadly applicable techniques in the MITRE ATT&CK framework because the Windows registry is both the central configuration store for the operating system and a well-understood target for attackers. Modifications range from high-impact (disabling Defender, adding persistence keys) to subtle (altering user interface behavior). This test sits at the subtle end: it sets `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoRun` to `1`, which activates a Group Policy setting that removes the **Run** dialog from the Start menu (Windows+R).

Disabling the Run dialog is relevant in adversarial scenarios because it degrades the victim's ability to quickly launch administrative tools, command prompts, or recovery utilities during an incident. An attacker with an established foothold might apply this alongside other UI restrictions to slow down manual investigation and response. The modification persists until removed, survives user logoff and logon, and applies per-user (HKCU) rather than system-wide.

Critically, this modification is made using the built-in `reg.exe` utility — a living-off-the-land approach that generates no alerts based on binary reputation and leaves no dropped payload. The full execution chain (`powershell.exe` → `cmd.exe` → `reg.exe`) is well-instrumented by both Security EID 4688 and Sysmon EID 1, making this a useful dataset for validating process chain detection logic.

In the defended variant, Windows Defender allowed this execution (registry modification with `reg.exe` is not in itself malicious) and generated a slightly larger event set due to its own background activity. The undefended variant here is essentially equivalent in technique execution.

## What This Dataset Contains

This dataset captures 114 events across three channels (93 PowerShell, 4 Security, 17 Sysmon) collected over a 5-second window (2026-03-14T23:48:54Z–23:48:59Z) on ACME-WS06 with Defender disabled.

**Process Creation Chain (Security EID 4688):**

Four EID 4688 events document the complete execution sequence:
1. `whoami.exe` — pre-test ART identity check
2. `cmd.exe` with command: `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRun /t REG_DWORD /d 1 /f`
3. `reg.exe` with command: `reg  add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRun /t REG_DWORD /d 1 /f`
4. `whoami.exe` — post-test identity check

The double-space between `reg` and `add` in event 3 is consistent with how Windows parses the command when `cmd.exe /c` strips the outer quotes — a minor but persistent artifact worth noting for exact-string matching (prefer regex or tokenized matching over exact command line strings).

**Sysmon Process Creates (EID 1):**

Four EID 1 events provide hash data and parent chain information for the key processes:

- `whoami.exe` (PID 3860): SHA256 `574BC2A2995FE2B1F732CCD39F2D99460ACE980AF29EFDF1EB0D3E888BE7D6F0`, IMPHASH `62935820E434AF643547B7F5F5BD0292`, parent GUID `{9dc7570a-f3e5-69b5-8611-000000000600}` (parent PowerShell), tagged `technique_id=T1033`
- `cmd.exe` (PID 4004): SHA256 `423E0E810A69AACEBA0E5670E58AFF898CF0EBFFAB99CCB46EBB3464C3D2FACB`, IMPHASH `D73E39DAB3C8B57AA408073D01254964`, full NoRun command line, tagged `technique_id=T1059.003`
- `reg.exe` (PID 6592): SHA256 `411AE446FE37B30C0727888C7FA5E88994A46DAFD41AA5B3B06C9E884549AFDE`, IMPHASH `1085BD82B37A225F6D356012D2E69C3D`, full reg add command line, tagged `technique_id=T1012`

The parent-child chain: PowerShell (PID tied to GUID `{9dc7570a-f3e5-...}`) → cmd.exe (PID 4004, GUID `{9dc7570a-f3ea-69b5-8b11-...}`) → reg.exe (PID 6592, parent GUID `{9dc7570a-f3ea-69b5-8b11-...}`).

**Sysmon Image Loads (EID 7):**

9 EID 7 events for the .NET CLR DLL sequence on the parent PowerShell process (PID 4292).

**Sysmon Process Access (EID 10):**

3 EID 10 events showing the parent PowerShell process accessing its child processes with `GrantedAccess: 0x1FFFFF`.

**Sysmon Named Pipe Create (EID 17):**

One EID 17 for the standard PowerShell host pipe `\PSHost.*.powershell`.

**PowerShell Script Block Logging (EID 4104):**

93 EID 4104 events, all PowerShell runtime boilerplate. The ART test framework invokes `cmd.exe` directly; no PowerShell functions are compiled for the actual registry modification.

## What This Dataset Does Not Contain

- **Registry value set event (Sysmon EID 13):** The Sysmon configuration does not capture registry write events for the `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` path. This is a notable gap — EID 13 (RegistryEvent SetValue) would directly show the `NoRun` value being written with the DWORD value `1`. The process chain (cmd.exe → reg.exe with the add command) is the primary evidence instead.
- **Rollback / cleanup of the registry modification:** The ART cleanup procedure reverses the change after the test, but the cleanup command does not appear in this dataset's collection window.
- **Policy effect events:** Windows does not generate an event when the Explorer Group Policy takes effect from a registry change. The modification's impact is only observable behaviorally (the Run dialog disappears) or by querying the registry.

## Assessment

This is a clean, complete execution of a simple registry modification technique. The process chain is fully documented across both Security EID 4688 and Sysmon EID 1 with hashes, command lines, and parent-child relationships. The technique itself (using `reg.exe` to modify an Explorer policy key) is straightforward to detect at the process creation level.

Compared to the defended variant (74 events: 34 PowerShell, 12 Security, 28 Sysmon), this undefended version (114 events) is slightly larger primarily due to the higher PowerShell EID 4104 count (93 vs. 34) — the Defender-disabled environment generates more PowerShell runtime events because Defender is not consuming system resources that would otherwise interrupt the event pipeline.

The Security channel is smaller here (4 vs. 12) because Defender's own process activity (MsMpEng.exe, MpDefenderCoreService.exe) contributes additional EID 4688 events in the defended variant that are absent here. This is a consistent pattern across the T1112 series: the defended datasets have more Security events because Defender itself generates process creations.

## Detection Opportunities Present in This Data

**EID 4688 / Sysmon EID 1 — reg.exe Adding NoRun to Explorer Policies:**
The `reg add` command targeting `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` with value name `NoRun` is a specific and rarely-benign command. The value name, path, and DWORD `1` together constitute a high-fidelity indicator.

**EID 4688 / Sysmon EID 1 — cmd.exe Spawned from PowerShell with reg add:**
The parent-child relationship `powershell.exe` → `cmd.exe /c reg add ...` is detectable through process ancestry analysis. Administrative uses of `reg.exe` run directly from cmd.exe or interactively; PowerShell spawning cmd.exe to run reg.exe is an indirect pattern worth alerting on when the target key is in a policy-related path.

**Sysmon EID 1 — reg.exe Hash Baseline:**
The reg.exe hash (SHA256 `411AE446FE37B30C0727888C7FA5E88994A46DAFD41AA5B3B06C9E884549AFDE`, IMPHASH `1085BD82B37A225F6D356012D2E69C3D`) provides a baseline for this version of reg.exe on Windows 11 22H2 build 22631. Changes to this hash in your environment would indicate a modified or replaced reg.exe binary.

**Policy Path Coverage:**
The `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` path is targeted by multiple T1112 tests in this series (NoRun, NoControlPanel, NoFileMenu, NoSetTaskbar, HideClock, HideSCAHealth, HideSCAPower). Monitoring for any `reg add` targeting this path, regardless of value name, provides broad coverage across this family of techniques.
