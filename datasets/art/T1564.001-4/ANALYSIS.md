# T1564.001-4: Hidden Files and Directories — Create Windows Hidden File with Attrib

## Technique Context

MITRE ATT&CK T1564.001 (Hidden Files and Directories) covers marking files with attributes that cause standard tools to omit them from directory listings. This test applies the Hidden (+h) attribute using `attrib.exe`, which is the most widely recognized form of file hiding on Windows. Files marked as hidden are excluded from `dir` output by default, do not appear in Windows Explorer with standard settings, and are skipped by many automated backup and inventory tools.

While simpler than the System attribute variant (T1564.001-3), hidden files are used pervasively in both commodity malware (configuration files, payloads staged in temp directories) and targeted intrusions. The `attrib.exe` binary is a signed Microsoft utility that is universally present on Windows systems.

## What This Dataset Contains

The dataset spans approximately 6 seconds (14:20:26–14:20:32 UTC).

**Process execution chain (Sysmon EID 1):**

The ART test framework launched PowerShell as SYSTEM, which spawned cmd.exe:

```
"cmd.exe" /c attrib.exe +h %%temp%%\T1564.001.txt
```

The `attrib.exe` process was invoked with the expanded path:

```
attrib.exe  +h C:\Windows\TEMP\T1564.001.txt
```

As with T1564.001-3, `attrib.exe` is captured in Sysmon EID 1 with `RuleName: technique_id=T1564.001,technique_name=Hidden Files and Directories` due to an explicit include rule in the sysmon-modular configuration. Both the cmd.exe wrapper and the attrib.exe execution are present with complete command lines.

**Security EID 4688:** Process creates for whoami.exe, cmd.exe, and attrib.exe.

**Security EID 4703:** Token right adjustment for SYSTEM.

**Sysmon EID 7 (Image Load):** DLL loads for PowerShell startup.

**Sysmon EID 17 (Pipe Created):** Named pipe for the PowerShell host.

**Sysmon EID 10 (Process Access):** PowerShell cross-process access to child processes.

**PowerShell EID 4103:** `Set-ExecutionPolicy -Bypass` invocation.

## What This Dataset Does Not Contain (and Why)

**No file creation event for the target file:** The file `T1564.001.txt` was staged by a prior ART setup step and is not created within this capture window.

**No Sysmon EID 13 (Registry Value Set):** Unlike T1564.001-3, there is no incidental registry activity from background services in this window.

**No file attribute change event:** Windows has no built-in audit event for attribute modifications via `SetFileAttributes`. The only telemetry is the process execution record.

**Fewer Security events than T1564.001-3:** This dataset has 12 Security events versus 12 in T1564.001-3, but notably lacks the W32Time registry artifact that appeared in test 3. The capture window is otherwise structurally identical.

**Object access auditing is disabled:** No file handle or SACL-based events are present.

## Assessment

This dataset is structurally nearly identical to T1564.001-3, with `+h` substituted for `+s`. Both are captured with equal fidelity through the attrib.exe command line. The differences between the hidden (`+h`) and system (`+s`) attribute variants are subtle: system-flagged files are treated as protected OS files and are harder to delete accidentally, while hidden files are simply omitted from default views. In practice, many adversaries apply both attributes (`+h +s`) simultaneously.

The sysmon-modular include rule for attrib.exe ensures capture regardless of attribute flag. This is a well-covered technique given the instrumentation configuration.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 (RuleName: T1564.001):** `attrib.exe` with `+h` flag on a file path in a temp or user-writable directory. Any `attrib.exe` invocation on non-OS paths with `+h` or `+s` flags warrants review.
- **Security EID 4688:** `attrib.exe` process creation with command line containing `+h`, particularly from parent processes like `cmd.exe` spawned by `powershell.exe` running as SYSTEM.
- **Comparison with T1564.001-3:** Detections for both `+s` and `+h` should be unified. Adversaries use both, and treating them as separate detection cases creates gaps.
- **Parent chain:** PowerShell → cmd.exe → attrib.exe, all running as SYSTEM in `C:\Windows\TEMP\`, is a reliable indicator of non-interactive automated execution.
- **Gap:** Attribute changes performed by custom code using the `SetFileAttributes` Win32 API directly produce no process execution telemetry and would be undetectable with this instrumentation configuration alone.
