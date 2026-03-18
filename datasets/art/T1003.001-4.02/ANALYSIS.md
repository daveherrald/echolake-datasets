# T1003.001-4: LSASS Memory — Dump LSASS.exe Memory using NanoDump

## Technique Context

NanoDump is a purpose-built LSASS dumping tool designed for stealth and detection evasion. Unlike ProcDump or comsvcs.dll, NanoDump implements its own memory reading logic, supports multiple dumping strategies (including NTFS transaction tricks and handle duplication), and produces dumps that are intentionally invalid according to the MiniDump format specification — requiring a repair step before offline analysis tools can process them. The invalid dump format was introduced specifically to prevent automated AV/EDR scanning of the dump content as it's written to disk.

In this test variant, the invocation is `nanodump.x64.exe -w "%temp%\nanodump.dmp"` — the default write-mode operation that creates a truncated minidump in the temp directory. The `-w` flag selects the write-to-disk mode, which produces the dump file before cleanup removes it. NanoDump runs as a standalone executable rather than through a LOLBin proxy, making its process creation event directly detectable.

The defended version showed `cmd.exe` exiting with status 0x1 (failure), confirming Defender blocked NanoDump before it could access LSASS. The undefended run should produce the dump file and the LSASS access event.

## What This Dataset Contains

The undefended execution produces 20 Sysmon events (6 EID 7, 5 EID 11, 4 EID 1, 4 EID 10, 1 EID 17), 104 PowerShell events (102 EID 4104, 2 EID 4103), and 4 Security EID 4688 events. The small Sysmon count means the 20-event sample has good coverage of the attack-specific events.

The **Sysmon channel** samples include:

**EID 1 (Process Create)**: `whoami.exe` (PID 2276), `cmd.exe` (PID 4092) with command line `"cmd.exe" /c C:\AtomicRedTeam\atomics\..\ExternalPayloads\na...` — the NanoDump launcher — and the cleanup phases. The `cmd.exe` wrapping NanoDump's execution is the primary process creation indicator since NanoDump itself would only appear in EID 1 if it matches the sysmon-modular include filter.

**EID 10 (Process Access)**: `powershell.exe` (PID 4308) accessing `whoami.exe` (PID 2276) with `GrantedAccess: 0x1FFFFF` and full call trace showing `ntdll.dll` → `System.Management.Automation.ni.dll` in the call stack. These are the test framework-level monitoring events. The 4 total EID 10 events in the dataset include these whoami accesses; whether a `nanodump.exe` → `lsass.exe` access event is among them depends on whether NanoDump's access patterns match the sysmon-modular ProcessAccess filter.

**EID 11 (File Create)**: 5 file creation events including the background `APPX.*.tmp` writes and potentially the `%TEMP%\nanodump.dmp` output file.

**EID 7 (Image Load)**: 6 DLL load events capturing PowerShell's .NET runtime initialization.

The **Security channel** shows the attack process chain: `whoami.exe` (PID 0x8e4), `cmd.exe` (PID 0xffc) — the NanoDump wrapper — `whoami.exe` (PID 0x1350), and `cmd.exe` (PID 0x7c8) for cleanup. The defended version's analysis noted `"cmd.exe" /c C:\AtomicRedTeam\atomics\..\ExternalPayloads\nanodump.x64.exe -w "%temp%\nanodump.dmp"` as the full command line in Security EID 4688 — this same command line is in the undefended dataset.

The **PowerShell channel** contains the `Invoke-AtomicTest T1003.001 -TestNumbers 2 -Cleanup` script block (note: the cleanup block specifies test 2, not test 4, which is a test framework artifact), plus the attack-specific script blocks. The 2 EID 4103 events may contain NanoDump's output.

The critical difference from the defended version is that NanoDump actually ran and accessed LSASS, with the resulting dump file written to `%TEMP%\nanodump.dmp`. The defended version's four Security EID 4688 events included an exit code of 0x1; the undefended run's cmd.exe exit code should be 0x0 (success).

## What This Dataset Does Not Contain

NanoDump's intentionally malformed dump output means that even if the dump file is present in the Sysmon EID 11 records, standard parsing tools cannot read it without the `--repair` post-processing step that NanoDump provides separately.

The dataset does not include any credential parsing activity following the dump creation. NanoDump produces the dump artifact, and the test ends.

As with other tests in this collection, the sysmon-modular ProcessCreate include-mode filter likely excludes `nanodump.x64.exe` from Sysmon EID 1, so the NanoDump process itself may only appear in the Security EID 4688 chain (via the wrapping `cmd.exe`) rather than as a direct Sysmon process creation event.

## Assessment

This dataset provides the NanoDump execution artifacts absent from the defended version: the full `cmd.exe` command line with the `-w "%temp%\nanodump.dmp"` argument visible in Security EID 4688, the potential Sysmon EID 10 LSASS access event, and the dump file creation in EID 11. NanoDump is sufficiently distinct from generic LSASS dumpers that its command-line signature (the `-w` flag with a `.dmp` output path) is a useful specific indicator in addition to the universal LSASS access detection. The dataset is useful for building detections that identify NanoDump by its command-line pattern and output file naming convention.

## Detection Opportunities Present in This Data

1. Sysmon EID 10 with `TargetImage` containing `lsass.exe` and `SourceImage` matching `nanodump.x64.exe` or `nanodump.exe` — the direct LSASS memory read event when NanoDump runs successfully.

2. Security EID 4688 with command line containing `nanodump.x64.exe` and `-w` with a `.dmp` output path in `%TEMP%` — direct command-line matching on the tool name and dump flag.

3. Sysmon EID 11 with `TargetFilename` matching `nanodump.dmp` in temp directories — the specific output file naming convention for NanoDump's write mode.

4. Security EID 4688 showing `cmd.exe` with a path referencing `ExternalPayloads\nan` (the NanoDump binary) combined with a successful exit code (0x0) versus the blocked version's 0x1 — exit code correlation distinguishes successful from blocked attempts.

5. Sysmon EID 1 or Security EID 4688 for any process from a user-writable staging path (like `C:\AtomicRedTeam\...\ExternalPayloads\`) with command-line arguments including `-w` and a dump output file — tool execution from staging locations with dump output flags.

6. PowerShell EID 4104 script blocks containing `nanodump` or the ART test invocation pattern `Invoke-AtomicTest T1003.001 -TestNumbers 4` — detecting the test framework invocation as a proxy for the technique.
