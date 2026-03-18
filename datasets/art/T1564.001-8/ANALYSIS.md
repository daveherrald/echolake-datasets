# T1564.001-8: Hidden Files and Directories — Hide Files Through Registry

## Technique Context

MITRE ATT&CK T1564.001 (Hidden Files and Directories) includes modifying Windows Explorer settings through the registry to suppress display of hidden and system files globally. This test sets two registry values:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowSuperHidden` → `0`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden` → `0`

`ShowSuperHidden = 0` disables the "Show protected operating system files" option, hiding all system-attributed files. `Hidden = 0` disables showing hidden files. Together, these settings cause Windows Explorer and the command prompt to omit all files with hidden or system attributes, affecting all users on the system. This is a broader, more persistent approach than using `attrib.exe` on individual files: rather than hiding specific files, it reconfigures the OS's disclosure behavior system-wide.

This technique is used by adversaries after deploying hidden-attribute files or directories, to prevent casual inspection from revealing them.

## What This Dataset Contains

The dataset spans approximately 6 seconds (14:20:48–14:20:54 UTC).

**Process execution chain (Sysmon EID 1):**

The ART test framework launched PowerShell as SYSTEM, which spawned cmd.exe with a compound command:

```
"cmd.exe" /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 0 /f & reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 0 /f
```

Two separate `reg.exe` processes were spawned in sequence:

```
reg  add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 0 /f
reg  add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 0 /f
```

Both `reg.exe` invocations are captured as Sysmon EID 1 with `RuleName: technique_id=T1012,technique_name=Query Registry` — a mislabeled rule name in the sysmon-modular configuration (T1012 is Registry Query, while this action is a registry write). The rule name label does not affect the captured data.

**Security EID 4688:** Confirms process creates for whoami.exe, cmd.exe, and both reg.exe instances, all as SYSTEM.

**Security EID 4703:** Token right adjustment.

**Sysmon EID 7 (Image Load):** DLL loads for PowerShell.

**Sysmon EID 17 (Pipe Created):** Named pipe for the PowerShell host.

**Sysmon EID 10 (Process Access):** PowerShell cross-process access to child processes.

**Sysmon EID 11 (File Create):** PowerShell profile startup data file written under the SYSTEM profile.

**PowerShell EID 4103:** `Set-ExecutionPolicy -Bypass` test framework invocation.

## What This Dataset Does Not Contain (and Why)

**No Sysmon EID 13 (Registry Value Set):** Despite two `reg.exe` invocations writing to `HKLM\...\Explorer\Advanced`, no Sysmon EID 13 events are captured for these writes. The sysmon-modular configuration targets specific high-value registry paths for EID 13 monitoring (Run keys, service registry paths, LSA paths, etc.); the Explorer Advanced key is not in that set. The writes are visible only through the `reg.exe` command lines.

**No Security EID 4657 (Registry Object Modified):** Object access auditing is disabled.

**No visual effect telemetry:** The actual behavior change — files becoming invisible in Explorer — generates no log events.

**No file-level events:** There are no attrib.exe or file attribute events in this dataset. This test modifies display settings, not individual file attributes.

## Assessment

The technique is captured via the `reg.exe` command lines, which fully expose the target registry keys and values being modified. However, the absence of Sysmon EID 13 means a detection that relies on registry value monitoring for `Explorer\Advanced` will find no evidence here. The `reg.exe` process execution approach is the only source of evidence in this dataset.

The mislabeled RuleName (`T1012,technique_name=Query Registry`) on the reg.exe process creates is worth noting for analysts consuming this data: the label is from the sysmon-modular rule that matched, not from automated technique identification. The actual technique is T1564.001 (registry-based file hiding), but Sysmon labeled it as T1012 because the matching rule was written for reg.exe broadly.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security EID 4688:** `reg.exe` command lines writing to `HKLM\...\Explorer\Advanced` with values `ShowSuperHidden` or `Hidden` set to `0`. These specific key/value combinations are high-confidence indicators when performed in a non-interactive, SYSTEM context.
- **Sysmon EID 1:** `cmd.exe` spawned by `powershell.exe` as SYSTEM with `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced` in the command string.
- **Behavioral:** The combination of disabling both `ShowSuperHidden` and `Hidden` in a single command string suggests deliberate pre-staged file hiding preparation rather than accidental misconfiguration.
- **Gap:** No Sysmon EID 13 is present for these registry writes. A registry monitoring rule targeting `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced` would provide independent, command-line-free evidence of the configuration change and would survive attempts to make the reg.exe invocation less visible (e.g., via PowerShell Set-ItemProperty).
