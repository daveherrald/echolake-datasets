# T1218.007-4: Msiexec — Execute Local MSI File with an Embedded EXE

## Technique Context

T1218.007-4 tests a Msiexec variant where the MSI package contains an embedded executable rather than an embedded script. During MSI installation, the custom action extracts the embedded EXE and runs it as a child process of `msiexec.exe`. This is a delivery mechanism: the attacker's payload binary arrives inside a seemingly legitimate Windows Installer package and executes through the trusted `msiexec.exe` binary.

The practical difference from the JScript variant (T1218.007-1) is that defenders who focus on script engine invocations (JScript, VBScript DLLs loading in msiexec) will miss this approach. The embedded EXE is extracted to a temporary path under `C:\Windows\Installer\` with a `.tmp` extension and executed directly. This means a signed MSI file can act as a dropper and launcher in a single operation.

The test MSI used here (`T1218.007_EXE.msi`) extracts an executable to `C:\Windows\Installer\MSI96B0.tmp` (or similar randomized name) and calls it with the argument `"Hello, Atomic Red Team from an EXE!"`.

The dataset was collected on ACME-WS06 (Windows 11 Enterprise, domain-joined to acme.local) with Windows Defender disabled.

## What This Dataset Contains

The dataset contains 150 total events: 107 PowerShell, 6 Security, 31 Sysmon, and 6 Application.

**Security EID 4688 captures the complete process chain:**

1. `"cmd.exe" /c c:\windows\system32\msiexec.exe /q /i "C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_EXE.msi"` — cmd.exe with the local MSI path
2. `c:\windows\system32\msiexec.exe /q /i "C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_EXE.msi"` — msiexec.exe performing the quiet install
3. `"C:\Windows\Installer\MSI96B0.tmp" "Hello, Atomic Red Team from an EXE!"` — the embedded executable extracted and run by the MSI custom action
4. `"C:\Windows\system32\whoami.exe"` — ATH framework success verification

The embedded EXE path `C:\Windows\Installer\MSI96B0.tmp` is notable: `C:\Windows\Installer\` is the directory where Windows Installer temporarily stages files during installation, and the `.tmp` extension masks the binary's true nature.

**Sysmon EID 1** captures the process creation chain with parent-child relationships:
- `powershell.exe` → `cmd.exe` (`RuleName: technique_id=T1059.003`)
- `cmd.exe` → `msiexec.exe` (`CommandLine: c:\windows\system32\msiexec.exe /q /i "...T1218.007_EXE.msi"`, `RuleName: technique_id=T1218`)
- Two `whoami.exe` executions under `powershell.exe` parent
- `cmd.exe` (empty command from cleanup)

**Sysmon EID 11 (File Created)** records 5 file creation events from the msiexec installation process. These include the MSI being copied to `C:\Windows\Installer\` for permanent storage and the temporary EXE being extracted. The extracted EXE itself (`MSI96B0.tmp` or similar) is created in `C:\Windows\Installer\` immediately before execution.

**Sysmon EID 10 (Process Access)** records 4 full-access events from PowerShell to `whoami.exe` and `cmd.exe`.

**Sysmon EID 7 (Image Load)** records 16 events in the PowerShell test framework process.

**Application log** records the full Windows Installer lifecycle: EID 1040 (transaction start), EID 1033 (install success), EID 11707 (product installed), EID 10000/10001, and EID 1042 (transaction end) — 6 events confirming successful MSI processing.

**PowerShell EID 4104** contains test framework boilerplate plus cleanup: `Invoke-AtomicTest T1218.007 -TestNumbers 4 -Cleanup -Confirm:$false 2>&1 | Out-Null`. Also includes `$ErrorActionPreference = 'Continue'` and `Set-ExecutionPolicy Bypass -Scope Process -Force`.

## What This Dataset Does Not Contain

The embedded executable's behavior after launch is not captured here beyond its process creation event. `MSI96B0.tmp` executes with its argument and exits; there are no network connections, file writes, or registry changes from it in this dataset because the test EXE is a simple proof-of-concept.

No Sysmon EID 3 (network connection) events appear, consistent with a local-only test without external communication.

No registry events document the MSI's product registration entries, which would normally appear in a real installation scenario.

The `.tmp` file itself is visible only in Security EID 4688 at execution time. In a real attack, defenders lacking Security 4688 coverage with command-line logging would not see what `MSI96B0.tmp` was called with.

## Assessment

This dataset demonstrates a fully successful undefended Msiexec embedded-EXE execution. The Security EID 4688 events uniquely expose the extracted EXE path (`C:\Windows\Installer\MSI96B0.tmp`) and its arguments, which is the most direct evidence of the technique. The Windows Installer application log entries confirm successful installation lifecycle completion.

Compared to the defended variant (39 Sysmon, 21 Security, 34 PowerShell, 6 Application), the undefended run produced fewer Security events (6 vs. 21), consistent with the absence of Defender-generated privilege audit events. Sysmon events are lower (31 vs. 39) because Defender wasn't scanning the process chain and adding process access noise.

## Detection Opportunities Present in This Data

**Security EID 4688:** Process creation event for `"C:\Windows\Installer\MSI96B0.tmp" "Hello, Atomic Red Team from an EXE!"` is the definitive indicator. In real attacks: any process spawned from `C:\Windows\Installer\` with a `.tmp` extension is extremely suspicious. Legitimate MSI custom actions do run executables, but with `.tmp` extensions from `C:\Windows\Installer\`, these should be correlated with the installing MSI.

**Security EID 4688 (msiexec):** `msiexec.exe /q /i` referencing an MSI in an atypical path (`C:\AtomicRedTeam\`) is suspicious. In real attacks: msiexec quiet-installs from temp directories, user profile paths, or downloaded locations.

**Sysmon EID 1:** The chain `cmd.exe → msiexec.exe` with the MSI path (`RuleName: technique_id=T1218`) and subsequent `whoami.exe` executions is tagged and preserved. The parent of `cmd.exe` is `powershell.exe`, which is unusual for real software installation.

**Sysmon EID 11 (File Created):** File creation events in `C:\Windows\Installer\` immediately followed by process creation from the same directory provide a create-then-execute pattern that can be detected with file creation and process creation correlation.

**Application Log EID 1033/11707:** The package name visible in application log events identifies what installed. In real attacks, the attacker-chosen package name would be recorded here.
