# T1219-7: Remote Access Tools — RemotePC Software Execution

## Technique Context

T1219 (Remote Access Tools) covers adversary use of legitimate remote access software — tools like TeamViewer, AnyDesk, GoToAssist, and in this case RemotePC — to maintain persistent, interactive access to compromised systems. These tools are challenging from a detection perspective because they operate over encrypted channels, use vendor-controlled relay infrastructure, and have real legitimate uses in enterprise environments.

RemotePC is a commercial remote desktop solution by IDrive Inc., offering unattended access, file transfer, and session recording. Attackers deploy it for the same reason they deploy other RATs: it blends with legitimate tooling, its traffic resembles normal remote support activity, and most endpoint security tools do not categorically block it.

This test attempts to execute RemotePC by calling `Start-Process` on a pre-staged binary at `C:\AtomicRedTeam\atomics\..\ExternalPayloads\RemotePC.exe`. The test fails because the binary was not staged at that path on this system — but the attempt is fully logged.

## What This Dataset Contains

**Security EID 4688** captures the PowerShell process creation with the execution attempt:

1. `powershell.exe` (PID 0x3c3c) spawned by the ART test framework `powershell.exe` (PID 0x4428) with command line: `"powershell.exe" &` — the full command line is truncated at the character limit in the Security log sample, but Sysmon EID 1 completes the picture.
2. A second `powershell.exe` (PID 0x4134) spawned with the cleanup command.

**Sysmon EID 1** captures the child `powershell.exe` (PID 15420) with full command line: `"powershell.exe" & {Start-Process "C:\AtomicRedTeam\atomics\..\ExternalPayloads\RemotePC.exe"}` — the exact command that attempted to execute RemotePC.

**PowerShell EID 4100** records the execution error: `"This command cannot be run due to the error: The system cannot find the file specified."` This confirms the failure was a missing binary, not a security control. The error occurs because `RemotePC.exe` was not pre-staged in `ExternalPayloads\`.

**Sysmon EID 7** (17 events) records `.NET` runtime and Defender DLLs loading into the PowerShell processes, along with `System.Management.Automation.ni.dll` — normal PowerShell initialization.

**Sysmon EID 17 (NamedPipe)** records two pipe creations: `\PSHost.<timestamp>.<pid>.DefaultAppDomain.powershell` — the standard PowerShell host communication pipe.

The capture window spans approximately 3 seconds (17:00:09 to 17:00:12 UTC).

Total event counts: 0 Application, 107 PowerShell, 4 Security (EID 4688), 26 Sysmon.

The undefended dataset has 26 Sysmon events versus 36 in the defended variant. The defended run's higher Sysmon count may include Defender scanning the `Start-Process` attempt against the missing binary path.

## What This Dataset Does Not Contain

Because `RemotePC.exe` was not present at the expected path, the binary never executed. There are no events showing RemotePC running, no network connections to RemotePC relay infrastructure (`199.83.x.x` or `api.remotepc.com`), and no file creation or registry modification artifacts from a RemotePC installation.

No **Sysmon EID 3** (network connection) events appear. The process creation failure occurred before any network activity.

The dataset documents a failed execution attempt, not successful RAT deployment. For a dataset showing RemotePC's actual runtime behavior, the binary would need to be pre-staged.

## Assessment

This dataset is most useful as a documented example of an attempted RAT deployment that failed due to a missing staged binary — a realistic scenario in real attack chains where a previous staging step failed or the attacker assumed a binary would be present. The attempt is fully logged: the PowerShell command line, the `Start-Process` invocation, and the resulting error are all captured. Compared to a successful execution, the dataset lacks network and file-system artifacts, but the initial execution attempt telemetry is intact and provides the command-line evidence needed to identify what was being attempted. The defended variant similarly shows a failed execution with slightly more Sysmon events.

## Detection Opportunities Present in This Data

The following behavioral observables are directly present in the event records:

- **Sysmon EID 1** captures `powershell.exe` executing `Start-Process "C:\AtomicRedTeam\atomics\..\ExternalPayloads\RemotePC.exe"`. The filename `RemotePC.exe` in a `Start-Process` command from an automated PowerShell session is a direct indicator, regardless of whether the execution succeeds.
- **Security EID 4688** shows nested PowerShell spawning (`powershell.exe` → `powershell.exe`) for the execution attempt. Nested PowerShell child processes spawned by SYSTEM for a single command are characteristic of automated attack tooling rather than interactive use.
- **PowerShell EID 4100** provides the error "The system cannot find the file specified" — confirming a binary was expected at `ExternalPayloads\RemotePC.exe`. Even a failed execution attempt leaks the attacker's intent and expected payload path.
- The path `C:\AtomicRedTeam\atomics\..\ExternalPayloads\` is the ART staging directory. In a real attack, the equivalent would be a user-writable temp directory or a working directory established during initial access. Detection logic watching `Start-Process` calls against paths outside of `Program Files`, `Windows`, or other standard locations applies here.
- **Sysmon EID 17** shows the PowerShell host pipe `\PSHost.<timestamp>.<pid>.DefaultAppDomain.powershell` being created. This is normal PowerShell telemetry that can be used to correlate which pipe creation event corresponds to which process, aiding in reconstructing the exact execution timeline.
