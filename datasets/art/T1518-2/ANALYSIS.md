# T1518-2: Software Discovery — Applications Installed

## Technique Context

T1518 (Software Discovery) covers adversary enumeration of the installed software inventory. Knowing what software is installed helps attackers identify exploitable versions, understand what security tools may be present, and blend in with expected software. The Uninstall registry hive (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*`) is the most common programmatic inventory source because it is accessible without elevation on most Windows systems and does not require WMI or external tooling. The 64-bit and 32-bit (Wow6432Node) paths together give a complete application list. PowerShell's `Get-ItemProperty` against these paths is a standard IT automation operation, which means this technique blends easily into normal administrative activity.

## What This Dataset Contains

The test executes a PowerShell script block that reads both the 64-bit and 32-bit Uninstall registry hives and formats the output:
```powershell
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -Autosize
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -Autosize
```

**Sysmon (Event ID 1, `technique_id=T1059.001`)** — The child `powershell.exe` process is captured with the full command line containing both `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` paths.

**Security (Event ID 4688)** — Matching process-create events with full command lines. The `powershell.exe` command line contains both registry paths in a single argument block.

**PowerShell (Event ID 4104)** — Two script block events capture the technique payload:
- The outer script block: `& {Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object ... | Format-Table -Autosize ...}`
- The inner block variant without the `&` wrapper.

These 4104 events are the primary evidence for detection — the specific registry path and the `Get-ItemProperty` cmdlet together form a precise indicator.

**PowerShell (Event ID 4103)** — Module logging is present but contains only test framework boilerplate (`Set-ExecutionPolicy`). The `Get-ItemProperty` call itself does not appear in 4103 in this dataset.

**Security (Event IDs 4689, 4703)** — Process exits and a token right adjustment for the SYSTEM context PowerShell are recorded.

## What This Dataset Does Not Contain

- No registry read (4663) events — object access auditing is not enabled, so you cannot see individual key reads within the Uninstall hive.
- No Sysmon Events 12/13 — these are read-only operations.
- No output of the installed software list. The results of `Get-ItemProperty` are displayed to stdout only; they do not appear in any event log.
- The Sysmon include-mode filter did not produce a Sysmon Event 1 for the `powershell.exe` that ran `Get-ItemProperty` directly (only the child process launched by the test framework was captured via the T1059.001 rule). The Security 4688 provides complementary coverage.

## Assessment

A solid, clean dataset for the most common software inventory enumeration pattern. The PowerShell 4104 script block capture is the highest-value event and directly supports string-match or regex detection on the Uninstall registry path in script blocks. The dataset is brief (6 seconds, 36 sysmon + 10 security + 37 PS events) and low-noise relative to the technique evidence, making it easy to build rules without extensive filtering. One improvement would be enabling SACL-based registry object access auditing to confirm the keys were successfully read.

## Detection Opportunities Present in This Data

1. **PowerShell 4104** — Script block containing `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` combined with `Get-ItemProperty` is a targeted but high-coverage indicator; legitimate software inventory tools typically use the same path, so context (parent process, user, time of day) should inform severity.
2. **PowerShell 4104** — Both 64-bit and 32-bit Uninstall paths queried in the same script block is more specific than either path alone and correlates with attacker tooling that seeks a complete inventory.
3. **Sysmon Event 1 / Security 4688** — `powershell.exe` spawned with a command line containing both `Uninstall\*` paths is anomalous; legitimate patch management tools typically call APIs, not interactive-style one-liners.
4. **Security 4688 parent-child** — `powershell.exe` (SYSTEM) spawning a child `powershell.exe` that performs registry enumeration at SYSTEM integrity is unusual on a domain workstation.
5. **Sysmon Event 1 rule tag `technique_id=T1059.001`** — The sysmon-modular annotation provides an immediate pivot for triage.
