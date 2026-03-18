# T1564.001-3: Hidden Files and Directories — Create Windows System File with Attrib

## Technique Context

MITRE ATT&CK T1564.001 (Hidden Files and Directories) covers adversary techniques for marking files with attributes that cause them to be hidden from standard directory listings. This test uses `attrib.exe` to apply the System (+s) attribute to a file, making it invisible to default `dir` and Windows Explorer views unless "Show protected operating system files" is explicitly enabled. Files marked as system are often excluded from automated scans and user-driven investigations because operators assume they are legitimate OS components.

The `attrib.exe` approach is notable because it requires no scripting capability — it is a built-in Windows binary that works in any command context, including cmd.exe batch files and early-stage shellcode droppers.

## What This Dataset Contains

The dataset spans approximately 6 seconds (14:20:04–14:20:10 UTC).

**Process execution chain (Sysmon EID 1):**

The ART test framework launched PowerShell as SYSTEM, which ran cmd.exe with the following command:

```
"cmd.exe" /c attrib.exe +s %%temp%%\T1564.001.txt
```

The expanded form, as executed by `attrib.exe`, was:

```
attrib.exe  +s C:\Windows\TEMP\T1564.001.txt
```

Both the cmd.exe invocation (with the `%%temp%%` variable, which is a batch-context variable expansion artifact) and the attrib.exe invocation (with the fully expanded path) are captured as separate Sysmon EID 1 records. Notably, `attrib.exe` is captured in Sysmon EID 1 with `RuleName: technique_id=T1564.001,technique_name=Hidden Files and Directories` — the sysmon-modular rule set explicitly matches `attrib.exe` as a suspicious binary, which is why this process create was captured under the include-mode filter.

**Sysmon EID 13 (Registry Value Set):** A registry write to `HKLM\System\CurrentControlSet\Services\W32Time\Config\Status\LastGoodSampleInfo` from `svchost.exe` — a time synchronization service updating its state, unrelated to the attack. This is ambient OS noise included because it falls within the capture window.

**Security EID 4688:** Process creates for whoami.exe, cmd.exe, and attrib.exe. The attrib.exe entry confirms the command line with the expanded temp path.

**Security EID 4703:** Token right adjustment for SYSTEM.

**Sysmon EID 10 (Process Access):** PowerShell cross-process access to whoami.exe and cmd.exe with `0x1FFFFF`.

**PowerShell EID 4103:** `Set-ExecutionPolicy -Bypass` test framework boilerplate.

## What This Dataset Does Not Contain (and Why)

**No file creation event for T1564.001.txt:** The file being marked as a system file was pre-staged by the ART test framework setup step. No Sysmon EID 11 records the original file creation within this window. Only the attribute modification is captured.

**No Sysmon EID 12 (Registry Key Create):** The W32Time registry write is a value set (EID 13), not key creation. No attack-related registry keys are created.

**No file attribute change event:** Windows does not log attribute changes as a distinct security event type. The only record of the `+s` attribute being applied is the `attrib.exe` command line itself.

**No object access auditing:** Object access auditing is disabled (`object_access: none`), so there are no file handle events or audit events for the modified file.

## Assessment

The technique is captured with high fidelity through the `attrib.exe` command line. Because sysmon-modular explicitly includes `attrib.exe` in its ProcessCreate include rules, this is one of the better-captured tests in this T1564.001 group — the process create is present in Sysmon and duplicated in the Security log. The exact target file path is visible in the command line.

The ambient Sysmon EID 13 from W32Time is a real-world OS artifact: time synchronization activity occurs continuously and its registry writes fall within test capture windows routinely. This is expected noise from a live Windows domain member.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 (RuleName: T1564.001):** `attrib.exe` invoked with `+s` flag on a file in a user-writable temp directory. The combination of system attribute and a non-OS path is suspicious.
- **Security EID 4688:** `attrib.exe` process creation with command line containing `+s` or `+h +s` patterns, especially on paths outside `C:\Windows\System32\` or standard OS locations.
- **Sysmon EID 1:** `cmd.exe` spawned by `powershell.exe` as SYSTEM with `attrib.exe` in the command string — parent-child chain.
- **Behavioral baseline:** `attrib.exe` invocations with `+s` on paths in `%TEMP%`, user profile directories, or application data folders warrant investigation, since legitimate OS use of `attrib.exe` with the system attribute targets specific protected OS files, not temp directories.
- **Gap:** The attribute change itself (the filesystem metadata update) is not directly observable. Detection depends entirely on the process execution record. If `attrib.exe` is replaced by direct API calls (e.g., `SetFileAttributes` in custom code), this detection path is bypassed.
