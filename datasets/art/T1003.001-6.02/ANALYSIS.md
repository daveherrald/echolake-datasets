# T1003.001-6: LSASS Memory — Offline Credential Theft With Mimikatz

## Technique Context

Offline credential theft with Mimikatz separates the dump creation and credential extraction into two distinct phases. In this test, the workflow is: (1) create an LSASS memory dump using a legitimate tool (such as Task Manager or a prior test's ProcDump run), then (2) run Mimikatz against the dump file offline using `sekurlsa::minidump <dump_file>` followed by `sekurlsa::logonpasswords full`. This separation is operationally useful because it moves the credential extraction phase off the target system — the dump can be created locally and analyzed on an attacker-controlled machine with no EDR installed.

The ART command line for this test is: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\x64\mimikatz.exe" "sekurlsa::minidump %tmp%\lsass.DMP" "sekurlsa::logonpasswords full" exit`. This invokes the Mimikatz binary directly with arguments specifying the dump file path and the commands to run against it. Critically, this test requires a pre-existing `lsass.DMP` file at `%TEMP%\lsass.DMP` — if no dump exists, Mimikatz will fail but still produce detectable telemetry.

In the defended version, Defender blocked Mimikatz execution with exit code `0xC0000022` before any parsing could occur. The undefended run allows Mimikatz to execute, though its success depends on whether an LSASS dump was previously created and placed at the expected path.

## What This Dataset Contains

This dataset contains 22 Sysmon events (7 EID 11, 6 EID 7, 4 EID 10, 4 EID 1, 1 EID 17), 104 PowerShell events (102 EID 4104, 2 EID 4103), and 11 Security events (6 EID 4688, 5 EID 4664) — notably including **5 EID 4664 (An attempt was made to create a hard link)** events, a channel not present in the defended dataset.

The **Security channel** EID 4664 events record hard link creation attempts for `Microsoft.People` UWP app assets: `C:\Program Files\WindowsApps\Microsoft.People_10.1909.12456.0_..._scale-100\Assets\People*.png` → `C:\Program Files\WindowsApps\Microsoft.People_10.2202.100.0_..._scale-100\Assets\People*.png`. These are legitimate Windows Update operations (linking files between People app versions) that happened to occur concurrently with the test. They appear in this dataset and not in the defended version because Defender's blocking of mimikatz.exe was faster than the update-related hard link operations — another example of how the undefended run captures more concurrent OS activity.

The **Security EID 4688** events show the attack process chain:
- `whoami.exe` (PID 0x1268)
- `cmd.exe` (PID 0x13d4, spawned by PowerShell PID 0x9a4) — the Mimikatz launcher
- `whoami.exe` (PID 0x1064)
- And additional processes from the cleanup/context check phases

The Sysmon EID 1 sample includes `cmd.exe` (PID 5076) with command line `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\...` — the Mimikatz invocation (path truncated in the sample). Also visible in Sysmon EID 1 is `cmd.exe` (PID 1668) in `C:\Windows\TEMP\` as the current directory — suggesting execution in the temp directory context.

The **Sysmon EID 10 (Process Access)** samples show `powershell.exe` (PID 2468) accessing `whoami.exe` (PIDs 4712 and 4196) with `GrantedAccess: 0x1FFFFF`. The 4 EID 10 events reflect test framework-level process access rather than Mimikatz accessing LSASS directly — Mimikatz processing an existing dump file does not require opening a process handle to `lsass.exe`, which is why no LSASS EID 10 events appear. This is expected for the offline technique variant.

The **PowerShell channel** EID 4103 output includes the `CommandInvocation(Write-Host): "DONE"` event with the full test framework context, indicating the test completed.

## What This Dataset Does Not Contain

Because this is an offline analysis test (Mimikatz reads from a dump file rather than from live LSASS memory), there are no Sysmon EID 10 events showing LSASS process access. The standard LSASS-access-based detection rules will not fire for this technique variant. This is the core detection challenge the technique was designed to address.

If the `%TEMP%\lsass.DMP` prerequisite file did not exist when this test ran, Mimikatz would have failed with an error message about being unable to open the file. The `DONE` output in PowerShell EID 4103 suggests the ART test framework reported completion, but this could reflect completion of the attempt rather than successful credential extraction.

The Mimikatz binary itself (`x64\mimikatz.exe`) does not appear in Sysmon EID 1 events because the sysmon-modular include-mode filter excludes it, similar to other external payload binaries.

## Assessment

This dataset is uniquely valuable because it represents the offline LSASS analysis workflow — the case where Sysmon EID 10 LSASS access events are intentionally absent. This challenges detection approaches that rely exclusively on process-access-to-LSASS as the primary indicator. The dataset demonstrates that Mimikatz execution is detectable through other means: the Security EID 4688 command line showing `mimikatz.exe sekurlsa::minidump` is a direct indicator, as is the presence of the Mimikatz binary in the execution chain. The concurrent EID 4664 hard link events and EID 4688 Windows Update-related process activity provide realistic environmental context, illustrating how credential theft telemetry appears alongside legitimate administrative activity in real environments.

## Detection Opportunities Present in This Data

1. Security EID 4688 with `ProcessCommandLine` containing `mimikatz.exe` and `sekurlsa::minidump` — a direct, high-fidelity match on the Mimikatz offline analysis command. This fires regardless of whether a dump file exists or whether the operation succeeds.

2. Security EID 4688 with `ProcessCommandLine` containing `sekurlsa::logonpasswords` — the credential extraction command that appears even in offline mode.

3. Sysmon EID 1 with `ParentImage` being `cmd.exe` and a command line referencing a binary path from `ExternalPayloads\x64\mimikatz.exe` — tool execution from the staging directory.

4. Sysmon EID 7 (Image Load) showing Mimikatz-specific DLL loads (notably `C:\Windows\System32\mimidrv.sys` or credential-related DLLs) in the `mimikatz.exe` process — while sysmon-modular may not create a ProcessCreate event for the binary, it may capture DLL loads.

5. File system detection: Sysmon EID 11 for the creation of `lsass.DMP` or similarly named dump files in `%TEMP%` — the prerequisite file that offline Mimikatz operations depend on.

6. The combination of a `.DMP` file present in `%TEMP%` (from a prior test run) and a subsequent `mimikatz.exe` invocation within the same session is a strong two-stage correlation opportunity that spans across test boundaries.
