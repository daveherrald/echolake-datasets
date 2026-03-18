# T1547.001-20: Registry Run Keys / Startup Folder — Add Persistence via Windows Context Menu

## Technique Context

T1547.001 covers persistence and privilege escalation through Windows registry run keys and startup mechanisms. This test targets the Windows Shell context menu extension registry path: `HKEY_CLASSES_ROOT\Directory\Background\shell\`. Entries written here appear as custom items in the right-click context menu that appears when a user right-clicks on the desktop background. By writing a `\command` subkey with a malicious executable as the default value, an adversary ensures their payload is launched each time any user right-clicks on the desktop.

This persistence mechanism differs from run keys in an important way: it does not fire automatically at logon. It requires user interaction (a right-click on the desktop). However, in practice this interaction is frequent in interactive user sessions, making it a reliable opportunity for payload execution that is tied to user presence rather than scheduled boot/logon events. It also operates from `HKEY_CLASSES_ROOT`, a hive that many registry-monitoring detection rules do not cover as thoroughly as `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`.

This dataset was collected on ACME-WS06 (Windows 11 Enterprise Evaluation, domain `acme.local`) with Windows Defender fully disabled via Group Policy. Compare with the defended variant in `datasets/art/T1547.001-20` for the same test against an active Defender installation.

## What This Dataset Contains

The test executed as `NT AUTHORITY\SYSTEM` via QEMU guest agent. A `cmd.exe` process runs `reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\Size Modify\command" /ve /t REG_SZ /d "C:\Windows\System32\calc.exe" /f` to install the context menu entry.

**Sysmon (17 events — EIDs 1, 7, 10, 17):**

EID 1 (ProcessCreate) captures four processes:
- `whoami.exe` (test framework identity check, tagged T1033)
- `cmd.exe` (tagged T1083) with full command line: `"cmd.exe" /c reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\Size Modify\command" /ve /t REG_SZ /d "C:\Windows\System32\calc.exe" /f`
- `reg.exe` (tagged T1083) with the same arguments: `reg  add "HKEY_CLASSES_ROOT\Directory\Background\shell\Size Modify\command" /ve /t REG_SZ /d "C:\Windows\System32\calc.exe" /f`
- A final `whoami.exe` at cleanup

The `cmd.exe` and `reg.exe` entries are annotated with `technique_id=T1083` rather than T1547.001 — the sysmon-modular rules tag these binaries by their general capability, not by the specific registry path being written.

**No Sysmon EID 13 (RegistrySetValue) is present in this dataset** for the `HKCR\Directory\Background\shell` path. The sysmon-modular include-mode registry monitoring rules do not cover `HKEY_CLASSES_ROOT` shell extension paths, so the registry write goes unrecorded by Sysmon. The persistence action is visible only through process creation auditing.

EID 7 (ImageLoad) accounts for 9 events covering PowerShell .NET runtime DLL loads. EID 10 (ProcessAccess) and EID 17 (PipeCreate) are standard test framework artifacts.

**Security (4 events — EID 4688):**

Four EID 4688 process creation events:
- `whoami.exe`
- `cmd.exe` with the full `reg add HKEY_CLASSES_ROOT\Directory\Background\shell\Size Modify\command` command line
- `reg.exe` with the same arguments
- A final process at cleanup

All processes ran as `NT AUTHORITY\SYSTEM`. The `HKEY_CLASSES_ROOT` path, the `Size Modify` context menu name, the `/ve` (default value) flag, and the `calc.exe` payload are all captured in plaintext in the EID 4688 command line fields.

**PowerShell (96 events — EIDs 4103, 4104):**

EID 4104 script blocks are PowerShell runtime boilerplate. The test action executes via `cmd.exe /c reg add` and generates no substantive PowerShell script blocks for the persistence action itself.

Compared to the defended variant (36 Sysmon, 12 Security, 34 PowerShell), the undefended run produces fewer events (17 Sysmon, 4 Security, 96 PowerShell). The defended variant's higher Sysmon count (36 vs. 17) and Security count (12 vs. 4) reflects additional test framework execution cycles logged in the defended environment.

## What This Dataset Does Not Contain

- No Sysmon EID 13 for the `HKCR\Directory\Background\shell` write — the sysmon-modular configuration does not monitor `HKEY_CLASSES_ROOT` shell extension paths.
- No user right-click interaction occurs during the test. `calc.exe` is never executed from the context menu.
- The `Size Modify` context menu entry is removed at cleanup; the cleanup `reg delete` command is not explicitly captured in the Security sample set but should be in the full `data/security.jsonl`.

## Assessment

This dataset demonstrates context menu persistence where the entire detection picture comes from process creation auditing rather than registry monitoring. Sysmon has zero coverage of the actual registry write. The Security EID 4688 log is the sole source showing both the target path (`HKEY_CLASSES_ROOT\Directory\Background\shell\Size Modify\command`) and the payload (`C:\Windows\System32\calc.exe`).

This mirrors the T1547.001-18 (RDP `StartupPrograms`) pattern where a specific registry path falls outside the sysmon-modular monitoring scope. Both cases underscore that process command line auditing provides coverage for registry operations that Sysmon's registry filters miss.

The undefended and defended runs are structurally identical for this technique — the telemetry difference is quantitative (event counts) rather than qualitative (which event types are present).

## Detection Opportunities Present in This Data

The following observable events in this dataset support detection:

- **Security EID 4688** recording `cmd.exe` or `reg.exe` with arguments referencing `HKEY_CLASSES_ROOT\Directory\Background\shell` — this path is rarely modified through `reg.exe` outside of adversarial tooling and some installer scripts. Any `\command` subkey write is worth investigating.

- **Security EID 4688** with `reg.exe` arguments containing `/ve` (default value write) combined with an executable path in the `/d` argument, targeting HKCR shell extension paths — this specific combination maps precisely to context menu command registration.

- **Sysmon EID 1** for `cmd.exe` (child of `powershell.exe`) spawning `reg.exe` with `HKEY_CLASSES_ROOT` in the arguments as `NT AUTHORITY\SYSTEM` — while HKCR is accessible to standard users for per-user shell extensions, SYSTEM-level writes to the machine-wide `Directory\Background\shell` path are unusual outside of software installation.

- **Absence of Sysmon EID 13**: as with T1547.001-18 and T1547.001-20, no registry write event appears in Sysmon for this persistence path. Any detection strategy for context menu persistence must account for this monitoring gap in sysmon-modular configurations.

- **The context menu name itself**: `Size Modify` in this test is arbitrary and adversary-controlled. The key name under `Directory\Background\shell\` is the command label visible in the right-click menu — a suspicious or non-standard label in this location combined with an executable in the `\command` default value is a high-confidence indicator.
