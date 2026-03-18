# T1491.001-3: Internal Defacement — ESXi DCUI Welcome Message via PuTTY plink

## Technique Context

T1491.001 (Internal Defacement) in this test targets VMware ESXi hypervisors rather than Windows endpoints. Ransomware groups targeting virtualized infrastructure (notably BlackCat/ALPHV, LockBit, and others with ESXi-specific encryptors) have been observed modifying the ESXi Direct Console User Interface (DCUI) welcome message to display ransom notes. The DCUI is visible to any administrator who accesses the physical console of the hypervisor host, making it a high-impact defacement location. This test simulates an attacker with network access to an ESXi host who uses PuTTY's command-line SSH client (`plink.exe`) from a compromised Windows workstation to run `esxcli system welcomemsg set` remotely.

The technique is notable because the Windows endpoint is only the launching point — the actual defacement occurs on the ESXi host over SSH. Windows telemetry captures the lateral movement attempt but not its outcome on the hypervisor.

## What This Dataset Contains

The execution chain is captured in Sysmon Event ID 1 and Security Event ID 4688. PowerShell launches `cmd.exe`, which pipes to `plink.exe`:

```
cmd.exe /c echo "" | "C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe"
  -batch "atomic.local"
  -ssh -l root -pw "password"
  "esxcli system welcomemsg set -m 'RANSOMWARE-NOTIFICATION'"
```

The `plink.exe` binary path (`C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe`) is present in the Sysmon Event ID 1 command line for the `cmd.exe` process. A second `cmd.exe` child process (`cmd.exe /S /D /c" echo "" "`) is also captured — this is the piped `echo ""` sub-shell. Both are spawned under PowerShell as the parent.

The dataset also captures Sysmon Event ID 17 (Pipe Created) for the PowerShell host pipe `\PSHost.*.powershell`, which is expected infrastructure for the ART test framework execution context. There are no file creation events for `plink.exe` itself, indicating the binary was already present on disk before the collection window.

The PowerShell channel contains only ART test framework boilerplate — `Set-StrictMode` and `Set-ExecutionPolicy -Bypass` script blocks — with no technique-specific PowerShell content, consistent with the technique being executed via a child `cmd.exe` process.

## What This Dataset Does Not Contain

- **No evidence of whether the SSH connection to the ESXi host succeeded**: The `plink.exe` invocation targeted `atomic.local` with credentials `root/password`. Whether the connection was established, the ESXi host existed, and the welcome message was actually changed is not observable from Windows telemetry. The dataset captures the attempt, not the outcome.
- **No Sysmon network connection event for plink.exe**: Sysmon-modular's include-mode ProcessCreate filtering captured `cmd.exe` (matching the T1059.003 rule) but `plink.exe` network connections are absent. `plink.exe` is not a LOLBin in the Sysmon config's network connection inclusion rules.
- **No file creation of `plink.exe`**: The binary was pre-staged at the ExternalPayloads path before the collection window. File creation and download of the tool are not present.
- **No ESXi-side telemetry**: The hypervisor DCUI modification (if it succeeded) would not appear in Windows event logs. Detecting the actual defacement requires ESXi syslog or DCUI monitoring.

## Assessment

This dataset provides useful Windows-side evidence of an SSH-based lateral movement attempt targeting a hypervisor. The command line visible in Sysmon and Security channels is specific and actionable: `plink.exe` with hardcoded credentials, a `-batch` flag (suppresses interactive prompts — consistent with scripted attack use), and `esxcli system welcomemsg set`. The `C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe` path is test-environment-specific, but real-world actors use `plink.exe` from various locations. The dataset is good for building detection rules around `plink.exe` usage with credentials in the command line and ESXi management commands. Its primary limitation is that the technique's actual impact on the ESXi target cannot be verified from this telemetry alone.

## Detection Opportunities Present in This Data

1. **`plink.exe` execution with `-l root` and `-pw` credentials in the command line** — Sysmon Event ID 1 and Security 4688 capture the full command line including hardcoded credentials; `plink.exe` with interactive credential flags (`-l`, `-pw`) in a non-interactive context is a strong indicator.
2. **`cmd.exe` spawned by `powershell.exe` with a pipe to `plink.exe` via `echo "" |`** — The `echo "" | plink.exe` pipe pattern (Sysmon Event ID 1, parent/child chain) is used to automate SSH interactive prompts and is not typical of legitimate administrative use.
3. **`esxcli` appearing as a command argument to `plink.exe` or any SSH tool** — The presence of `esxcli system welcomemsg set` as an SSH command argument indicates ESXi management operations via remote tool, a technique consistent with ransomware operators targeting virtualized environments.
4. **`plink.exe` with `-batch` flag** — The batch mode flag suppresses host key prompts and is specifically used in automated/scripted attack scenarios; legitimate administrative use rarely suppresses all interactive prompts in this way.
5. **`plink.exe` executed from `C:\AtomicRedTeam\` or non-standard paths** — Tool execution from staging directories rather than installed application paths (e.g., `C:\Program Files\PuTTY\`) is a general indicator of opportunistic tool use.
