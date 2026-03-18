# T1562.010-2: Downgrade Attack — ESXi - Change VIB Acceptance Level to CommunitySupported via ESXCLI

## Technique Context

MITRE ATT&CK T1562.010 (Downgrade Attack) includes actions that weaken security controls
to permit further exploitation. VMware ESXi hosts enforce a VIB (vSphere Installation Bundle)
acceptance level hierarchy: `VMwareCertified` → `VMwareSigned` → `PartnerSupported` →
`CommunitySupported`. Lowering the acceptance level to `CommunitySupported` allows installation
of unsigned or community-authored VIBs, including attacker-deployed backdoor VIBs (as seen
in UNC3886 operations targeting VMware infrastructure). This test simulates the Windows-side
execution: connecting to an ESXi host via SSH using `plink.exe` and issuing the ESXCLI
acceptance level change command.

## What This Dataset Contains

The test attempts to connect to a target ESXi host via SSH using `plink.exe`:

```
cmd.exe /c echo "" | "C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe"
  "atomic.local" -ssh -l "root" -pw "pass"
  -m "C:\AtomicRedTeam\atomics\T1562.010\src\esx_community_supported.txt"
```

Security EID 4688 records the `cmd.exe` process create with the full `plink.exe` command line,
including the target hostname (`atomic.local`), credentials (`root`/`pass`), and the remote
command script path. Sysmon EID 1 captures the same with the `technique_id=T1059.003`
annotation from the sysmon-modular rule.

Sysmon EID 10 (ProcessAccess) shows `powershell.exe` accessing spawned `cmd.exe` processes,
flagged with the `technique_id=T1055.001,DLL Injection` rule annotation from sysmon-modular.
Sysmon EID 11 records PowerShell profile data files written during startup.

## What This Dataset Does Not Contain (and Why)

`plink.exe` itself does not appear as a process creation event in Sysmon EID 1. The
sysmon-modular include-mode ProcessCreate filter does not include `plink.exe`, so it was not
captured by Sysmon — but Security EID 4688 confirms the `cmd.exe` invocation containing the
full `plink.exe` command. No network connection event (Sysmon EID 3) for the SSH attempt
appears; `plink.exe` was likely blocked by Windows Defender before establishing a connection
(the target `atomic.local` does not exist in this test environment), or the process exited
before network activity was recorded.

No ESXi-side telemetry is present — this dataset captures only the Windows workstation events.
No actual VIB acceptance level change is confirmed; the test represents the attempt, not a
successful ESXi modification.

## Assessment

The key forensic evidence is Security EID 4688 capturing the `plink.exe` invocation with
plaintext credentials (`-l "root" -pw "pass"`) and the target host. In a real intrusion this
command would contain actual ESXi host IP addresses and credentials recovered from the
environment. The command structure — piping `echo ""` into `plink.exe` with `-m` for a remote
command file — is a recognizable pattern for non-interactive SSH command execution from
Windows. The dataset provides clean process creation telemetry for this pattern regardless of
whether the SSH connection succeeded.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `plink.exe` (or equivalent SSH CLI tools) with `-m` flag and ESXi
  target hostnames, combined with credentials passed as command-line arguments.
- **Sysmon EID 1**: `cmd.exe` command line containing `plink.exe` with SSH flags (`-ssh`,
  `-l`, `-pw`) — plaintext credential exposure in process arguments.
- **Process ancestry**: `powershell.exe` → `cmd.exe` launching an SSH client with hardcoded
  credentials targeting infrastructure hostnames (`.local` domain, IP ranges associated with
  hypervisor management networks).
- **Behavioral**: Any use of `plink.exe`, `putty.exe`, or other SSH tools with `-pw`
  (plaintext password) and `-m` (remote command file) arguments is indicative of scripted
  lateral movement or infrastructure manipulation.
