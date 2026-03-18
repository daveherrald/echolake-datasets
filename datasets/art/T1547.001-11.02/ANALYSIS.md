# T1547.001-11: Registry Run Keys / Startup Folder — Change Startup Folder (HKCU Modify User Shell Folders Startup Value)

## Technique Context

T1547.001 covers Registry Run Keys and Startup Folder persistence. This test is the per-user counterpart to T1547.001-10: instead of modifying the all-users `Common Startup` location in HKLM, this test redirects the per-user startup folder via `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Startup`. Windows uses this value to determine where to find per-user startup items at logon. Changing it to an attacker-controlled directory causes executables placed there to run at logon for the affected user only.

This HKCU variant requires no administrative privileges — any user can modify their own `User Shell Folders\Startup` value — making it usable by lower-privilege adversaries in addition to SYSTEM-level attackers. The technique bypasses detection logic focused on traditional Run key monitoring because no entry is added to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`; only the path consulted by the existing startup folder mechanism is changed.

The test creates `C:\Windows\Temp\atomictest\`, copies `calc.exe` there, and sets the `Startup` value to point to that directory.

A key differentiator from T1547.001-10: in this test, Sysmon EID 13 (RegistrySetValue) successfully captures the `User Shell Folders\Startup` modification, whereas the HKLM `Common Startup` write in T1547.001-10 was not captured. This difference reflects the sysmon-modular rule's specific include pattern for the HKCU path.

## What This Dataset Contains

The dataset spans 4 seconds (2026-03-17 17:08:58–17:09:02 UTC) on ACME-WS06 (`acme.local`), executing as `NT AUTHORITY\SYSTEM`.

**Sysmon (40 events — Event IDs 1, 7, 10, 11, 13, 17, 29):**

Sysmon EID 1 (ProcessCreate, 4 events):

1. `whoami.exe` — test framework context check, tagged `technique_id=T1033`
2. `powershell.exe` — tagged `technique_id=T1083`, full command line:
   ```
   "powershell.exe" & {New-Item -ItemType Directory -path "$env:TMP\atomictest\"
   Copy-Item -path "C:\Windows\System32\calc.exe" -destination "$env:TMP\atomictest\"
   Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Startup" -Value "$env:TMP\atomictest\"}
   ```
3. `whoami.exe` — second context check
4. `powershell.exe` — cleanup script

Sysmon EID 13 (RegistrySetValue, 1 event) tagged `technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder`:
- `TargetObject: HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Startup`
- `Details: C:\Windows\TEMP\atomictest\`
- Set by `powershell.exe` as `NT AUTHORITY\SYSTEM`

This is the direct registry artifact for the persistence mechanism — the value that redirects Windows' startup folder lookup. Its capture by EID 13 makes this dataset more forensically complete than T1547.001-10 for the registry dimension.

Sysmon EID 29 (FileExecutableDetected, 1 event) records `C:\Windows\Temp\atomictest\calc.exe` with hashes:
- SHA256: `9C2C8A8588FE6DB09C09337E78437CB056CD557DB1BCF5240112CBFB7B600EFB`
- SHA1: `5D77804B87735E66D7D1E263C31C4EF010F16153`

The same executable is written here as in T1547.001-10, confirming identical payload staging.

Sysmon EID 11 (FileCreate, 3 events) records `calc.exe` written to `C:\Windows\Temp\atomictest\` and PowerShell startup profile data.

Sysmon EID 7 (ImageLoad, 24 events), EID 10 (ProcessAccess, 4 events), and EID 17 (PipeCreate, 3 events) are standard PowerShell initialization artifacts.

**Security (4 events — Event ID 4688):**

Four process creation events: two `whoami.exe` invocations, one `powershell.exe` with the full test command line, and one `powershell.exe` cleanup invocation. The `powershell.exe` entry shows the `Set-ItemProperty` targeting the HKCU Startup path.

Unlike T1547.001-10 (which had only 3 Security events), this dataset captures 4 — likely because the cleanup PowerShell invocation is recorded here. There are no EID 4624 logon events, consistent with the undefended environment's leaner audit configuration.

**PowerShell (101 events — Event IDs 4103, 4104):**

ScriptBlock logging captures the test script, including `Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Startup" -Value "$env:TMP\atomictest\"`. The cleanup script that removes the staged payload and restores the original `Startup` value is also captured.

## What This Dataset Does Not Contain

- **No logon execution:** No user logon occurs during the test window, so the staged `calc.exe` in the redirected startup folder does not execute.
- **Cleanup restores original value:** The ART cleanup script removes the `atomictest` directory and presumably restores the `Startup` value. The restored value write is not in the available samples.
- **No WMI/logon events:** As with T1547.001-10, the undefended environment does not generate logon or privilege auditing events in this dataset.

## Assessment

T1547.001-11 produces more complete telemetry than T1547.001-10 specifically because the sysmon-modular configuration includes the HKCU `User Shell Folders\Startup` path in its EID 13 include rules while excluding the HKLM `User Shell Folders\Common Startup` path. The presence of EID 13 here makes the registry modification directly observable without requiring inference from command lines.

The two datasets (T1547.001-10 and -11) together illustrate a practical coverage asymmetry: HKCU startup folder path modification is detected by registry monitoring; HKLM Common Startup path modification is not, with current sysmon-modular defaults.

## Detection Opportunities Present in This Data

- **Sysmon EID 13:** `TargetObject` matching `HKU\*\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Startup` with a `Details` value pointing to a non-standard path (e.g., `C:\Windows\Temp\`). The `User Shell Folders\Startup` value changing to a temp directory is a high-confidence indicator of this technique.
- **Sysmon EID 29 (FileExecutableDetected):** An executable written to the same directory that `Startup` now points to, by a scripting host. The combination of a startup folder redirect (EID 13) followed immediately by an executable write (EID 29) to the redirected path is a strong composite signal.
- **Sysmon EID 1 / Security EID 4688:** `powershell.exe` command line containing `Set-ItemProperty` targeting `HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` with `-Name "Startup"`. The specific key path in a `Set-ItemProperty` call is uncommon outside attack tooling.
- **PowerShell EID 4104:** `Set-ItemProperty ... "User Shell Folders" -Name "Startup"` combined with `Copy-Item` staging an executable to the new path, both in the same ScriptBlock, provides high-confidence process-level context.
