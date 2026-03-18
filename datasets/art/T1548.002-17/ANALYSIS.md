# T1548.002-17: Bypass User Account Control — UACME Bypass Method 61

## Technique Context

T1548.002 (Bypass User Account Control) covers techniques that silently elevate process privileges without triggering a UAC consent prompt. UACME method 61 is one of the numbered exploits in the UACME collection targeting auto-elevate trust relationships in Windows. Like other UACME methods, it is invoked through `Akagi64.exe`, which takes a method number and optional command-line payload. Method 61 exploits a specific auto-elevate COM object or hijackable binary path to launch a payload with elevated integrity.

## What This Dataset Contains

The dataset captures approximately 5 seconds of activity on ACME-WS02 (Windows 11 Enterprise, domain member of acme.local).

**Sysmon Event 1** records the core process activity:
- `whoami.exe` spawned by `powershell.exe` (the ART pre-execution check, User: NT AUTHORITY\SYSTEM)
- `cmd.exe` with the UACME invocation: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\61 Akagi64.exe"`
  - Parent: `powershell.exe`, `CurrentDirectory: C:\Windows\TEMP\`
  - This is structurally identical to test 16 except for the method number

**Sysmon Event 10** records `powershell.exe` opening both `whoami.exe` and `cmd.exe` with `GrantedAccess: 0x1FFFFF`, flagged under the DLL Injection rule — this reflects the Invoke-AtomicRedTeam process creation mechanism.

**Sysmon Events 7** (image loads) show three sets of DLL loads into separate `powershell.exe` instances, covering the same rule annotations as test 16 (T1055, T1059.001, T1574.002, `urlmon.dll`).

**Sysmon Events 11** record PowerShell startup profile data creation in the SYSTEM profile path.

**Sysmon Event 17** records named pipe creation for each PowerShell host instance.

**Security 4688/4689**: Process creation and exit events for `whoami.exe`, `powershell.exe`, `cmd.exe`, and `conhost.exe`. The Security log does not capture command-line details in the rendered Message field for this capture (field not populated in the 4688 message).

**PowerShell 4104/4103**: The ART test framework emits two `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force` invocations. No UACME-specific PowerShell content — the test invokes Akagi64.exe as a pre-built binary.

## What This Dataset Does Not Contain (and Why)

**No elevated process spawned by the bypass**: UACME method 61 did not produce a visible elevated child process. As with method 59, there is no Security 4688 showing a `TokenElevationTypeFull` (type 2) process created from Akagi's auto-elevate mechanism.

**No Sysmon ProcessCreate for Akagi64.exe**: The sysmon-modular include-mode ProcessCreate filter does not match `Akagi64.exe` by name; only processes matching known-suspicious patterns appear in Sysmon Event 1.

**No network activity**: UACME does not make network connections. A Sysmon Event 3 is present but is a Windows Defender connection approximately 9 hours after the test and is unrelated.

**No registry events**: Unlike some UAC bypass methods, UACME method 61 does not write to registry keys that match the Sysmon registry monitoring rules in this configuration. No Event 13 appears.

**No file drop events beyond PowerShell profile data**: Akagi64.exe was pre-staged in `ExternalPayloads`; no download or file creation for the payload itself appears in this window.

## Assessment

UACME method 61 was attempted but the data does not show a successful elevated process spawn. The dataset is structurally similar to test 16: the `cmd.exe` wrapper invoking Akagi is captured, but Akagi64.exe itself is invisible to Sysmon due to the include-mode filter. The dataset provides strong evidence of the attempt and demonstrates the telemetry pattern for UACME-style invocations on a current Windows 11 build.

## Detection Opportunities Present in This Data

- **Sysmon Event 1 / Security 4688**: `cmd.exe` with a command line referencing `ExternalPayloads\uacme\` and a numeric method argument is a direct match for UACME execution.
- **Path pattern**: Any execution from `C:\AtomicRedTeam\ExternalPayloads\uacme\` on a production workstation is immediately suspicious regardless of method number.
- **Sysmon Event 10**: `powershell.exe` opening child `cmd.exe` or `Akagi64.exe` with full access (`0x1FFFFF`) from a SYSTEM session with no interactive desktop is worth investigating.
- **Process lineage anomaly**: `powershell.exe` running as SYSTEM → `cmd.exe` in `C:\Windows\TEMP\` → unknown binary is an unusual chain on a domain workstation.
- **Binary hash correlation**: Logging hashes for all `cmd.exe` spawns allows correlation across multiple UACME test executions even when the method numbers differ.
