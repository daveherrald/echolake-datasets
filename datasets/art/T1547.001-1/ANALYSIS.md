# T1547.001-1: Reg Key Run — Registry Run Key Persistence

## Technique Context

T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder) is the most common persistence mechanism observed in the wild. It appears in commodity malware, ransomware, APT toolkits, and red team frameworks. The concept is simple: write a value to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (or the HKLM equivalent), and Windows will execute that program every time the user logs in.

Its ubiquity makes it a first-priority detection for any SOC. The detection community focuses on:

- **Sysmon EID 13 (RegistryValueSet)**: Any write to `\CurrentVersion\Run` or `\CurrentVersion\RunOnce`. This is the highest-fidelity detection because it captures the exact key, value name, and value data.
- **Sysmon EID 1 / Security 4688**: Process creation of `reg.exe` with `ADD` and `\Run` in the command line.
- **PowerShell 4104**: `Set-ItemProperty` or `New-ItemProperty` targeting Run keys (for the PowerShell-native variant of this technique).

This ART test uses the simplest approach: `REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"`.

## What This Dataset Contains

This is one of the cleanest datasets in the collection for detection rule development.

The **Sysmon EID 13 (RegistryValueSet)** event is textbook:

```
EventType: SetValue
TargetObject: HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run\Atomic Red Team
Details: C:\Path\AtomicRedTeam.exe
Image: C:\Windows\system32\reg.exe
RuleName: technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder
```

This single event tells you everything: which registry key was written, what value was set (the executable path that will run at logon), and which process performed the write. Sysmon's own rule engine correctly tagged it as T1547.001. A detection rule keying on `TargetObject` containing `\CurrentVersion\Run\` would fire with high confidence and low false-positive rates.

The full **process chain** is captured in both Sysmon EID 1 and Security 4688:

```
powershell.exe (PID 1192, SYSTEM)
  → cmd.exe /c REG ADD "HKCU\...\Run" /V "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"
    → reg.exe ADD "HKCU\...\Run" /V "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"
```

Both Sysmon and Security provide SHA256 hashes, user context (NT AUTHORITY\SYSTEM), integrity level (System), and working directory (`C:\Windows\TEMP\`). A detection engineer has enough here to build rules at multiple levels of abstraction — from exact command-line matching to behavioral parent-child chain analysis.

## What This Dataset Does Not Contain

**The PowerShell channel has no technique signal.** All 34 events are internal PowerShell error-formatting scriptblocks (`Set-StrictMode` boilerplate) and `Set-ExecutionPolicy Bypass` test framework setup. This is because the ART test dispatches the registry write via `cmd.exe /c REG ADD` — an external process call, not a PowerShell-native cmdlet. PowerShell ScriptBlock Logging only captures PowerShell code, so the `REG ADD` command is invisible to it.

This is actually a realistic blind spot. Many attackers drop to `cmd.exe` for registry operations precisely because it generates less PowerShell telemetry. A complete detection strategy for T1547.001 must cover both the `reg.exe` command-line variant and the PowerShell-native `Set-ItemProperty` variant. Other tests in this collection (T1547.001-2 through T1547.001-14) cover additional variants.

**The HKCU path resolved to `HKU\.DEFAULT`** because the test ran as SYSTEM. The SYSTEM account's HKCU hive maps to `.DEFAULT` in the registry. A real user-context attack would show `HKU\S-1-5-21-<domain_SID>-<RID>\Software\...` instead. Detection rules that match on the literal string `HKCU` would miss the `HKU\.DEFAULT` variant, and vice versa. Rules should match on the path component `\CurrentVersion\Run\` regardless of the hive prefix.

**No Sysmon EID 12 (RegistryObjectAddOrDelete)** for key creation. Only EID 13 (value set) is present, because the `\Run` key already existed — `reg.exe` just added a new value to it. If the key didn't exist, you'd see a key creation event first.

## Assessment

This is a **strong dataset** for T1547.001 detection development. The Sysmon EID 13 event alone provides a complete, high-fidelity detection artifact with the registry path, value, and responsible process. The process chain is clean and fully visible in both Sysmon and Security channels.

The limitations are scope-related rather than quality-related: this covers only the `reg.exe` command-line variant of Run key persistence. Production detection coverage also needs to handle `Set-ItemProperty`/`New-ItemProperty` (PowerShell), direct Win32 API calls (`RegSetValueEx`), WMI-based registry writes, and Group Policy-based autostart entries. The broader T1547.001 test collection in this repository addresses some of these.

One additional nuance: the test writes a non-existent executable path (`C:\Path\AtomicRedTeam.exe`). A detection enrichment that checks whether the referenced executable actually exists on disk, and whether it is signed, would add significant value in a production environment — a Run key pointing to a nonexistent or unsigned binary is almost certainly malicious or orphaned.

## Detection Opportunities Present in This Data

1. **Registry write to Run key** (Sysmon EID 13): Match `TargetObject` containing `\CurrentVersion\Run\` with any `EventType: SetValue`. This is the canonical detection and fires cleanly on this data.

2. **reg.exe command-line matching** (Sysmon EID 1 / Security 4688): Process creation where `CommandLine` contains `REG` + `ADD` + `\CurrentVersion\Run`. The `/F` flag (force, no prompt) in a non-interactive context adds suspicion.

3. **Parent-child chain anomaly**: `powershell.exe → cmd.exe → reg.exe` writing to Run keys, running as SYSTEM from `C:\Windows\TEMP\`, is not a pattern that legitimate software produces. The working directory alone is a useful contextual indicator.

4. **Temporal clustering**: `whoami.exe` execution (T1033, reconnaissance) followed within seconds by a Run key write (T1547.001, persistence), both from the same parent PowerShell process running as SYSTEM. This pattern of recon-then-persist from a single session is worth building composite detection rules for.
