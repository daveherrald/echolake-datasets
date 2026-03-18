# T1202-2: Indirect Command Execution — forfiles.exe

## Technique Context

T1202 (Indirect Command Execution) describes the use of legitimate system utilities to proxy the execution of commands, with the goal of making the resulting process tree appear more benign or bypassing controls that focus on direct invocations of specific tools. `forfiles.exe` is a Windows utility designed to run commands against files matching a search pattern, but its `/c` parameter accepts arbitrary command strings — including `cmd.exe /c <payload>`. Because `forfiles.exe` is a signed Microsoft binary, it may pass application whitelisting controls that block third-party executables, and process-based detections that alert on direct `calc.exe` or payload invocations may not fire if the parent is `forfiles.exe`.

Detection programs focus on `forfiles.exe` executions where the `/c` argument does not reference typical file processing operations, and particularly on cases where the launched child process is unexpected relative to forfiles' legitimate use cases.

## What This Dataset Contains

This dataset captures a complete and successful forfiles.exe abuse execution. The process chain documented across Security EID 4688 and Sysmon EID 1 is:

`powershell.exe` → `cmd.exe` → `forfiles.exe` → `calc.exe`

The Security channel provides 6 EID 4688 events documenting all four processes in this chain plus additional cleanup invocations. The key `forfiles.exe` command line visible from the Security events is: `forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe`, run from within `cmd.exe /c forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe`. The result is `calc.exe` (PID 0x4760) spawning as a child of `forfiles.exe`.

Sysmon EID 1 captures two cmd.exe process creations — the primary forfiles invocation and a cleanup command later in the sequence. `whoami.exe` appears twice, once before and once after the main technique, as part of the ART test framework execution validation.

Sysmon EID 22 captures a DNS query from Windows Defender's `MsMpEng.exe` process for `_ldap._tcp.pdc._msdcs.acme.local` resolving to `acme-dc01.acme.local` (192.168.4.10). This is Defender performing a routine domain service check and is not related to the technique being tested.

The PowerShell channel records 107 events (104 EID 4104, 3 EID 4103): these are the ART test framework setup blocks (Set-ExecutionPolicy Bypass, Write-Host "DONE") plus the standard PowerShell StrictMode boilerplate. The Application channel records 1 event: `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON`, which is the test framework re-enabling Defender after test completion.

The Sysmon channel totals 40 events with a notable composition: 18 EID 22 (DNS queries), 10 EID 7 (DLL loads), 5 EID 1 (process creation), 4 EID 10 (process access), 2 EID 11 (file creation), and 1 EID 17 (named pipe). The high DNS query count (18) reflects Defender's background domain health checks during the test window.

## What This Dataset Does Not Contain

No network connection events (Sysmon EID 3) are present for the technique itself — the forfiles execution is purely local and involves no network activity. There are no registry modification events (Sysmon EID 13) since this technique does not require registry changes.

The dataset does not contain Sysmon events for the `forfiles.exe` binary itself loading DLLs (EID 7), which would be present in a Sysmon configuration that includes all image loads rather than using rule-based filtering. The actual `forfiles.exe` process creation is captured in Security EID 4688 but — depending on the Sysmon configuration's include rules — may not generate a Sysmon EID 1 event if forfiles.exe is not in the monitored binary list. In this dataset, the Security channel provides the most complete process creation coverage.

## Assessment

This dataset is one of the cleanest examples of indirect command execution available in this collection. The full process chain (powershell.exe → cmd.exe → forfiles.exe → calc.exe) is captured with command lines in both the Security and Sysmon channels, and the calc.exe process creation confirms the technique executed successfully. In the defended variant (Sysmon: 28, Security: 15, PowerShell: 34), the technique also executed — Defender does not block forfiles.exe abuse by default — so both datasets contain the core technique artifacts. The undefended dataset is larger primarily due to the expanded PowerShell test framework logging (107 vs. 34 events) rather than any meaningful difference in technique coverage.

For detection engineers, this dataset illustrates the key challenge with forfiles.exe abuse: the technique is simple, uses a fully signed Microsoft binary, requires no special privileges, and produces no file writes or network connections. Detection relies entirely on process lineage and argument analysis. The parent-child relationship `forfiles.exe` → `calc.exe` (or any non-file-processing binary) is the principal detection signal, and it is clearly present in this dataset.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1**: `forfiles.exe` with `/c` argument where the argument is not a file-oriented operation but a direct binary invocation (`calc.exe`, `cmd.exe`, `powershell.exe`, etc.)
- **Security EID 4688 / Sysmon EID 1**: Process lineage showing `forfiles.exe` as parent of a process that is unusual for file enumeration work — any interactive application or interpreter is suspicious
- **Security EID 4688**: `cmd.exe /c forfiles ...` as a child of `powershell.exe` represents a two-level indirection chain (PowerShell → cmd → forfiles) that is characteristic of scripted technique execution
- **Sysmon EID 10**: PowerShell process accessing the newly created child processes (whoami.exe, cmd.exe) with full rights (0x1FFFFF) indicates the orchestrating process is monitoring its launched children
- **Baseline awareness**: `forfiles.exe` invocations in enterprise environments are rare outside of specific administrative scripts; any forfiles execution on a user workstation warrants scrutiny
