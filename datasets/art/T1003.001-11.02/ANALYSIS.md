# T1003.001-11: LSASS Memory — Dump LSASS with createdump.exe from .Net v5

## Technique Context

`createdump.exe` is a diagnostic utility shipped with the .NET Core 3.x and .NET 5+ runtimes. Its intended purpose is to create crash dumps of .NET applications for debugging, but it accepts a PID argument and can dump any process — including LSASS — when run with sufficient privileges. This makes it a Living Off the Land Binary (LOLBin) for credential dumping: no external tooling needs to be introduced to the system if the .NET runtime is already installed, and the binary is Microsoft-signed.

The technique illustrates a broader class of attacks that exploit diagnostic utilities to avoid bringing custom tools to disk. Detection is complicated by the fact that `createdump.exe` is a legitimate utility with a legitimate use case in developer and devops environments. Detection strategies focus on the process creation event for `createdump.exe` with a PID argument that resolves to `lsass.exe`, Sysmon EID 10 process access events targeting LSASS, and the creation of dump files in writable directories. The tool is less commonly allowlisted than ProcDump, which has seen wider adoption in enterprise tooling, so its appearance outside developer workstations is inherently suspicious.

This specific test uses PowerShell to resolve the .NET 5 runtime path dynamically: `$exePath = resolve-path "$env:ProgramFiles\dotnet\shared\Microsoft.NETCore.App\5*\createdump.exe"`. In the defended dataset, this technique failed because .NET 5 was not installed on the test system — an infrastructure gap rather than a Defender block. In this undefended run, the same prerequisite check applies.

## What This Dataset Contains

The undefended execution of this test captures 3,095 Sysmon events (3,067 EID 11, 16 EID 7, 4 EID 1, 4 EID 10, 2 EID 17, 2 EID 3) and 109 PowerShell events (107 EID 4104, 2 EID 4103) alongside 4 Security EID 4688 process creation events.

The **PowerShell channel** includes the `Import-Module` test framework setup block, the cleanup block `Invoke-AtomicTest T1003.001 -TestNumbers 11 -Cleanup`, and 107 EID 4104 script block events covering both the test execution and boilerplate. The 2 EID 4103 module pipeline output events likely capture the error output from the failed `Resolve-Path` call — the defended analysis noted this error verbatim: `NonTerminatingError(Resolve-Path): "Cannot find path 'C:\Program Files\dotnet\shared\Microsoft.NETCore.App' because it does not exist."` The undefended run will produce the same error because the test environment simply does not have .NET 5 installed, regardless of Defender status.

The **Security channel** (4 EID 4688) shows `whoami.exe` (PID 0x8ec), `powershell.exe` (PID 0x460), `whoami.exe` (PID 0xb18), and `powershell.exe` (PID 0x17a8) — the pre-execution and cleanup process pairs.

The **Sysmon channel** contains 2 EID 3 (Network Connection) events, which are new compared to the defended version. These connections may reflect the test framework checking for the prerequisite .NET runtime or performing a dependency download, or they may be incidental background connections. The 16 EID 7 image loads capture DLLs loaded by PowerShell during the resolution attempt.

The notable difference from the defended version (46 sysmon, 10 security, 59 powershell) is that the undefended run has proportionally similar Security and PowerShell event counts but 3,095 Sysmon events versus 46. This inflation comes from the background EID 11 file creation activity — the technique itself failed identically in both runs.

## What This Dataset Does Not Contain

Because .NET 5 is not installed on ACME-WS06, `createdump.exe` was never located, launched, or executed. This means:

- No Sysmon EID 1 (Process Create) for `createdump.exe`
- No Sysmon EID 10 (Process Access) targeting `lsass.exe`
- No Sysmon EID 11 file creation for `C:\Users\...\AppData\Local\Temp\dotnet-lsass.dmp` or any equivalent dump file
- No credential extraction artifacts

The technique failure here is purely environmental — a missing runtime dependency — and has nothing to do with Defender being enabled or disabled. This dataset is therefore not differentiated from the defended version in terms of its coverage of the actual credential dumping phase.

## Assessment

This dataset is primarily useful as a negative example: it documents what LSASS dumping attempts via .NET diagnostic utilities look like when the prerequisite runtime is absent. The PowerShell EID 4103 error output showing the `Resolve-Path` failure provides ground truth for detecting failed precondition checks in credential dumping scripts. For environments where .NET 5 is installed, this dataset shows where the telemetry gaps would be — the actual `createdump.exe` process creation and LSASS access events — that an undefended run with the runtime present would produce. For tuning purposes, the PowerShell EID 4104 script blocks describing the dynamic path resolution pattern are useful for writing behavioral rules that catch the reconnaissance phase before the dump tool even runs.

## Detection Opportunities Present in This Data

1. PowerShell EID 4104 script blocks containing `Resolve-Path` with a glob pattern against `$env:ProgramFiles\dotnet\shared\Microsoft.NETCore.App` — this dynamic path resolution pattern is specific to the `createdump.exe` LOLBin technique.

2. PowerShell EID 4103 module output capturing the `NonTerminatingError(Resolve-Path)` message — even a failed attempt is logged and detectable.

3. Sysmon EID 1 (in environments where .NET 5+ is installed) showing `createdump.exe` launched with a numeric PID argument that matches the LSASS process ID — this is the primary runtime indicator for successful technique execution.

4. Security EID 4688 showing `powershell.exe` spawning a child process that resolves to `createdump.exe` — when the prerequisite is met, this will appear in the Security channel alongside the command line showing the LSASS PID.

5. Sysmon EID 3 (Network Connection) events from `powershell.exe` during the ART test framework's prerequisite check phase — these two network connections in the undefended run indicate external dependency resolution that could be suppressed or replaced with local artifacts in real attacks.

6. Detection of the `Get-Process lsass` cmdlet in PowerShell EID 4104 script blocks — this is a reconnaissance step that precedes the dump call and is detectable before the more sensitive LSASS access occurs.
