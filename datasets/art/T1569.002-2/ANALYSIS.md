# T1569.002-2: Service Execution — Use PsExec to execute a command on a remote host

## Technique Context

T1569.002 (Service Execution) test 2 covers PsExec, Sysinternals' remote execution tool that
works by copying a service binary to the target, creating a service, starting it, and deleting
it — all over SMB. PsExec is one of the most widely documented adversary tools, used in APT
campaigns, ransomware deployment, and red team engagements for over a decade. Its telemetry
footprint is well-studied: it generates Service Installation events on the target, network
connections to SMB (445/tcp), and characteristic named pipe activity. This test runs PsExec
against `localhost` (the same host), which exercises the local PsExec workflow without
requiring a second target system.

## What This Dataset Contains

The dataset spans approximately 5 seconds (14:30:03–14:30:08 UTC) from ACME-WS02.

**Sysmon Event 1 (Process Create)** captures:
1. `whoami.exe` (ART pre-flight, tagged T1033)
2. `cmd.exe` with the full PsExec invocation: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\PsExec.exe" \\localhost -i -u DOMAIN\Administrator -p P@ssw0rd1 -accepteula "C:\Windows\System32\calc.exe"` (tagged T1059.003)

The command line reveals:
- The source path for PsExec: `C:\AtomicRedTeam\atomics\..\ExternalPayloads\PsExec.exe`
- The target: `\\localhost`
- Credentials: `-u DOMAIN\Administrator -p P@ssw0rd1` (hardcoded in the ART test)
- The payload: `calc.exe`
- The flag: `-accepteula` (suppresses the interactive EULA dialog)

**Sysmon Event 10 (Process Access)** records PowerShell opening `whoami.exe` and `cmd.exe`
with `GrantedAccess: 0x1FFFFF` — the ART test framework monitoring its child processes.

**Sysmon Events 7 and 11** show standard PowerShell DLL loading and profile file creation.

**Security 4688/4689** record `whoami.exe`, `powershell.exe`, and `conhost.exe` lifecycle
under SYSTEM. Note: `cmd.exe` running PsExec and PsExec.exe itself do not appear in
Security 4688 in the bundled dataset — they may have been excluded during the window-based
filtering, or the events fell outside the exact 5-second window.

**PowerShell 4104 (Script Block Logging)** captures the ART boilerplate but the PsExec
command itself runs via `cmd.exe`, not directly from PowerShell — so only the outer wrapper
and error-handling fragments appear in PS logs, not the PsExec command.

## What This Dataset Does Not Contain (and Why)

**No PsExec.exe process create event in Sysmon.** The sysmon-modular include-mode ProcessCreate
rules do not include `PsExec.exe` by name or hash. `PsExec.exe` is launched as a child of
`cmd.exe`, and the rule set's include criteria (LOLBins, accessibility tools, specific tool
names) do not match `PsExec.exe` from `ExternalPayloads\`. Security 4688 would capture it
but is not present in the bundled events for PsExec.

**No System Event 7045 or Sysmon Event 13 for the PSEXESVC service.** PsExec installs a
service named `PSEXESVC` on the target host when running against a remote system. In a
localhost scenario, this service installation would appear in System and Sysmon logs, but
the System log is not collected in this dataset, and Sysmon Event 12/13 for the service
registry keys is absent — possibly because the test completed too quickly, the service
install did not complete, or the collection window was narrow.

**No network events for SMB (445/tcp).** PsExec uses SMB to communicate, but Sysmon Event 3
for port 445 from `PsExec.exe` is not present. This may indicate the tool failed (Defender
or the SCM may have blocked it), or the network connection was not captured in the window.

**No evidence of `calc.exe` executing.** No process create event for `calc.exe` appears,
suggesting PsExec did not successfully start the payload on localhost. This is consistent
with Windows Defender blocking PsExec execution (exit code `0xC0000022` — access denied —
is commonly returned when Defender quarantines PsExec on modern systems).

## Assessment

The critical signal in this dataset is in Sysmon Event 1: `cmd.exe` with a full PsExec
command line including hardcoded credentials (`DOMAIN\Administrator -p P@ssw0rd1`), target
(`\\localhost`), and payload (`calc.exe`). The `ExternalPayloads\PsExec.exe` source path
and `-accepteula` flag are additional indicators. In a real attack scenario, these would
point to an operator using a pre-staged tool with credential material.

The absence of PsExec's characteristic service installation and network activity strongly
suggests the execution was blocked by Defender before it could establish remote communication.

## Detection Opportunities Present in This Data

- **Sysmon Event 1 / Security 4688**: `PsExec.exe` or `psexec64.exe` in process command
  lines, especially with `\\` target notation, `-accepteula`, and `-u`/`-p` credential flags.

- **Security 4688**: `cmd.exe` with a command line containing `PsExec.exe \\` with embedded
  credentials is a high-confidence lateral movement indicator when command-line logging is on.

- **PowerShell 4104**: In this test, the PS log shows the outer test framework; in real attacks,
  `Invoke-Command` or direct PsExec calls from PowerShell scripts would appear in 4104.

- **Network (not in this dataset)**: SMB connections (port 445) from `PsExec.exe` to remote
  hosts followed by service installation on the target is the definitive multi-host signal.

- **System 7045 (not in this dataset)**: On the target host, service installation of
  `PSEXESVC` with `ImagePath` pointing to a temporary path is the canonical PsExec indicator.
