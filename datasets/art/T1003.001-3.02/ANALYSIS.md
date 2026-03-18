# T1003.001-3: LSASS Memory — Dump LSASS.exe Memory using direct system calls and API unhooking

## Technique Context

Outflank-Dumpert is a purpose-built LSASS dumping tool that bypasses EDR hooks by using direct system calls (`syscalls`) instead of the standard Windows API, and by unhooking user-mode monitoring before accessing LSASS memory. Most EDR products monitor LSASS access by hooking functions like `NtOpenProcess`, `NtReadVirtualMemory`, and `MiniDumpWriteDump` in user-mode memory. Dumpert avoids these hooks by invoking the underlying `syscall` instruction with the appropriate system call numbers directly, bypassing the hooked wrappers entirely. It also reads the clean copy of NTDLL from disk and maps it into memory to restore unhooked function stubs before executing.

This technique represents the evasion evolution of straightforward LSASS dumping. While Sysmon's kernel-level EID 10 (ProcessAccess) monitoring cannot be bypassed by user-mode unhooking (Sysmon hooks at the kernel level), some EDR products' user-mode hooks can be evaded. Detection for Dumpert relies on the filesystem artifact (`C:\windows\temp\dumpert.dmp` — the hardcoded output path in Outflank-Dumpert), the process execution chain showing a tool running from `ExternalPayloads\`, and privilege escalation events preceding the dump attempt.

The defended version showed Defender blocking Outflank-Dumpert.exe before execution with exit status 0x1, and no LSASS access events appeared. The undefended run should show the syscall-level LSASS access and the resulting dump file.

## What This Dataset Contains

This dataset is notable for containing **4 Security EID 5379 (Credential Manager Read)** events — a channel not seen in the defended version. These events record that the SYSTEM account enumerated stored credentials from Windows Credential Manager during the test window. This is a significant addition that appears specifically in the undefended run and reflects what the tool's execution triggers in the authentication subsystem.

The **Security channel** (9 events: 4 EID 5379, 4 EID 4688, 1 EID 4702) provides the full picture:
- Four EID 5379 events with `Read Operation: Enumerate Credentials` on behalf of `ACME-WS06$ (S-1-5-18)` — these Credential Manager read operations occur as Outflank-Dumpert or its downstream effects trigger Credential Manager access during LSASS interaction
- Four EID 4688 events: `whoami.exe` (PID 0x11b8), `cmd.exe` (PID 0x688, spawned by PowerShell PID 0xc2c with command line `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\O...`), `whoami.exe` (PID 0x1214), and `cmd.exe` (PID 0xcc8, the cleanup command `"cmd.exe" /c del C:\windows\temp\dumpert.dmp >nul 2> nul`)
- The cleanup command `del C:\windows\temp\dumpert.dmp` confirms the dump file at the hardcoded Dumpert output path was created — the cleanup is deleting it

The **Sysmon channel** (24 events: 13 EID 11, 4 EID 10, 4 EID 1, 2 EID 7, 1 EID 13) captures:
- EID 1 (Process Create): `cmd.exe` (PID 1672) with command line `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\O...` — Outflank-Dumpert.exe being launched, and the cleanup `cmd.exe` (PID 3272) with `"cmd.exe" /c del C:\windows\temp\dumpert.dmp >nul 2> nul` showing the artifact cleanup
- EID 10 (Process Access): `powershell.exe` (PID 3116) accessing `whoami.exe` processes (PIDs 4536 and 4628) with `GrantedAccess: 0x1FFFFF` — test framework-level process monitoring
- EID 13 (Registry Value Set): a registry modification captured during the test window
- The 13 EID 11 events include `APPX.*.tmp` background files and should include `C:\windows\temp\dumpert.dmp`

The cleanup command `del C:\windows\temp\dumpert.dmp` is the most definitive artifact confirming full technique execution. Outflank-Dumpert hardcodes its output to `C:\windows\temp\dumpert.dmp`, and the cleanup script only runs if the test completed successfully. The defended version had no cleanup of this file because the tool never ran.

The **PowerShell channel** (105 EID 4104, 2 EID 4103) includes the PowerShell EID 4103 output block with `CommandInvocation(Write-Host): "DONE"` confirming the test reported successful completion to the ART test framework.

## What This Dataset Does Not Contain

Despite Dumpert's syscall-based LSASS access, Sysmon EID 10 events targeting `lsass.exe` are not visible in the 20-event sample. The 4 EID 10 events in the dataset access `whoami.exe` rather than `lsass.exe`. Sysmon's kernel-level monitoring theoretically should capture syscall-based access, but the sysmon-modular ProcessAccess filter may exclude `Outflank-Dumpert.exe` from the ProcessAccess monitoring because it isn't in the include-mode source process list. This is a meaningful limitation for rule testing.

The actual `Outflank-Dumpert.exe` process does not appear in Sysmon EID 1 events because the sysmon-modular configuration uses include-mode filtering for ProcessCreate, and the external payload binary is not in the monitored process list.

## Assessment

The cleanup command visible in both Security EID 4688 and Sysmon EID 1 — `del C:\windows\temp\dumpert.dmp` — is the clearest confirmation of successful execution in this dataset. The Security EID 5379 Credential Manager read events are a unique artifact of the undefended run that doesn't appear in the defended version, providing an additional detection dimension for this technique. The lack of Sysmon EID 10 LSASS access events in the sample is a useful data point about the limits of include-mode filtering against this specific tool. For detection engineering, this dataset is most valuable for: the hardcoded Dumpert output path (`C:\windows\temp\dumpert.dmp`) as a file-based indicator, the Security EID 5379 Credential Manager enumeration events, and the cleanup command as a post-hoc indicator.

## Detection Opportunities Present in This Data

1. Sysmon EID 11 with `TargetFilename` matching `C:\windows\temp\dumpert.dmp` — Outflank-Dumpert's hardcoded output path is a specific, high-confidence indicator for this tool.

2. Security EID 4688 with `ProcessCommandLine` containing `del C:\windows\temp\dumpert.dmp` — even the cleanup operation is a forensic indicator that the dump was successfully created.

3. Security EID 5379 (Credential Manager Read) by SYSTEM or elevated accounts during the same time window as suspicious process creation events — this correlation was visible in the undefended run and absent from the defended version.

4. Security EID 4688 with `NewProcessName` containing `cmd.exe` and command line beginning `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\` for any executable from the payload staging directory — tool execution from lateral transfer staging paths.

5. Sysmon EID 1 showing `cmd.exe` with a command line referencing a path containing `ExternalPayloads` followed by a binary name that does not match known system utilities — the generic pattern for staged external tool execution.

6. Correlation of EID 4688 cleanup commands containing file deletion of `.dmp` files from `%TEMP%` within a short time window of other credential-access-indicative process creation events — cleanup of dump artifacts is itself evidence of prior successful execution.
