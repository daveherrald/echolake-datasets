# T1134.002-1: Create Process with Token — Access Token Manipulation via GetToken.ps1

## Technique Context

T1134.002 Create Process with Token describes adversaries stealing a privileged access token and using it to spawn a new process under that elevated security context. While T1134.001 focuses on impersonation (temporarily assuming another identity), T1134.002 specifically creates a new child process that inherits the stolen token — producing a persistent new process running under the target security context.

This test uses a custom PowerShell script `GetToken.ps1` from the ART atomics directory. The script uses P/Invoke to call the Windows API function `CreateProcessAsUser()` or `CreateProcessWithTokenW()`, passing a token duplicated from the `lsass.exe` process. Spawning a process from lsass's token is the most direct form of SYSTEM privilege acquisition available to an attacker who already has SeDebugPrivilege or SYSTEM context.

The full command executed:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
$owners = @{}
gwmi win32_process |% {$owners[$_.handle] = $_.getowner().user}
Get-Process | Select ProcessName,Id,@{l="Owner";e={$owners[$_.id.tostring()]}}
& "C:\AtomicRedTeam\atomics\T1134.002\src\GetToken.ps1"; [MyProcess]::CreateProcessFromParent((Get-Process lsass).Id,"cmd.exe")
```

This script:
1. Enumerates running processes and their owners via WMI (`gwmi win32_process`)
2. Displays a process list with ownership
3. Executes `GetToken.ps1` which loads the `MyProcess` .NET class via Add-Type
4. Calls `[MyProcess]::CreateProcessFromParent((Get-Process lsass).Id,"cmd.exe")` — spawning `cmd.exe` with lsass's SYSTEM token as the parent process token

This is a realistic adversarial pattern: enumerate processes to identify privileged targets, then create a new process with a stolen token.

## What This Dataset Contains

The dataset captures 39 Sysmon events, 4 Security events, 126 PowerShell events, and 2 Application events recorded on ACME-WS06 with Windows Defender fully disabled.

The technique execution is recorded in Security EID 4688. The spawned PowerShell child command line is:

```
"powershell.exe" & {Set-ExecutionPolicy -Scope Process Bypass -Force
$owners = @{}
gwmi win32_process |% {$owners[$_.handle] = $_.getowner().user}
Get-Process | Select ProcessName,Id,@{l="Owner";e={$owners[$_.id.tostring()]}}
& "C:\AtomicRedTeam\atomics\T1134.002\src\GetToken.ps1"; [MyProcess]::CreateProcessFromParent((Get-Process lsass).Id,"cmd.exe")}
```

Sysmon EID 1 records this spawned PowerShell with full hashes: SHA256 `3247BCFD...`, IMPHASH `AFACF6DC...`.

The command line contains several analytically significant elements:
- `gwmi win32_process` — WMI process enumeration to identify process owners
- `GetToken.ps1` — local token manipulation script
- `[MyProcess]::CreateProcessFromParent((Get-Process lsass).Id,"cmd.exe")` — explicit invocation targeting `lsass.exe` by PID to spawn `cmd.exe`

The reference to `lsass.exe` by name in the process creation command line is a direct indicator of LSASS-targeting token manipulation.

Sysmon EID 10 records two PowerShell process access events, both with `GrantedAccess: 0x1FFFFF`. The Sysmon config on this host flags process access to certain high-value targets; the access to `lsass.exe` itself (which `GetToken.ps1` must perform to duplicate its token via `OpenProcess()`) should be present in the full dataset as a Sysmon EID 10 with `TargetImage: lsass.exe` — this event would be among the most significant in the full dataset.

Sysmon EID 17 records two PowerShell named pipe creations (standard PSHost pipes).

Sysmon EID 11 records `StartupProfileData-NonInteractive` creation for the SYSTEM PowerShell profile — standard initialization artifact.

The Application channel contains 2 events (EID 15). These are Windows Event Log warning or error events logged by an application during the test window. Their content is not sampled but likely reflect the `GetToken.ps1` script's behavior (e.g., an error from the token duplication attempt or a .NET runtime notification).

This dataset's defended variant count of 132 Security events stands out dramatically compared to this dataset's 4 Security events. In the defended run, Defender generated 128 additional Security events — primarily process creation events from Defender's scanning infrastructure — triggered by `GetToken.ps1` accessing lsass. In the undefended run, Defender's inspection processes never ran, so the Security channel is minimal.

## What This Dataset Does Not Contain

The most significant absent event is Sysmon EID 10 with `TargetImage: C:\Windows\System32\lsass.exe`. This event would directly record `powershell.exe` (or `GetToken.ps1`'s compiled code) opening `lsass.exe`. It should be present in the full dataset and represents the primary process injection/access indicator for this technique.

No Security EID 4656 or EID 4663 for handle access to lsass — Process tracking in the Security channel records process creation, not API-level handle operations.

The `cmd.exe` process that `CreateProcessFromParent` would spawn is not recorded in this Security/Sysmon sample. If the token creation succeeded, `cmd.exe` running as SYSTEM with lsass's parent process would be in the full dataset as a distinctive Sysmon EID 1 event with an unusual parent PID.

## Assessment

This is a high-value dataset for lsass-targeting token manipulation. The verbatim command line in EID 4688 / Sysmon EID 1 contains direct references to `lsass`, `GetToken.ps1`, and `CreateProcessFromParent` — each of which is a meaningful detection indicator on its own and collectively form a strong behavioral signature for token theft.

The most analytically interesting aspect of this dataset in comparison with the defended variant is the extreme Security event count discrepancy (4 vs. 132). This documents concretely how much telemetry Defender's scanning generates when it responds to lsass access: 128 additional events in the defended run, entirely absent here. This has practical implications for detection teams: Defender's response activity can actually enrich the Security channel with process creation records that help analysts understand the attack scope.

Researchers should prioritize querying the full dataset files for Sysmon EID 10 events targeting `lsass.exe`, which is the ground-truth indicator of the token theft operation.

## Detection Opportunities Present in This Data

**`GetToken.ps1` with `CreateProcessFromParent((Get-Process lsass).Id,"cmd.exe")` in a PowerShell command line.** Security EID 4688 and Sysmon EID 1 record the full attack chain verbatim. `GetToken.ps1` by name is a rare string; the `CreateProcessFromParent` call with `lsass` as an argument makes this unambiguous.

**`gwmi win32_process` combined with process owner enumeration.** The command line contains `gwmi win32_process |% {$owners[$_.handle] = $_.getowner().user}` — a WMI-based process ownership enumeration pattern frequently used by attackers to identify which SYSTEM-context processes are available for token theft.

**Reference to `lsass` in PowerShell command arguments.** Sysmon EID 1 and Security EID 4688 record `(Get-Process lsass).Id` in the command text. Any PowerShell command line containing the string `lsass` in a process creation context should be treated as high-priority.

**Sysmon EID 10 against lsass.exe.** While not in this sample, the full dataset should contain a Sysmon EID 10 event recording `powershell.exe` opening `lsass.exe`. This event, when present, is one of the highest-fidelity process-based lsass access indicators available without ETW kernel-level monitoring.

**Application EID 15 correlated with lsass access.** The two Application channel events coinciding with the technique execution may reflect error or audit events from the token duplication process. These application-layer events correlated with the process chain provide additional context.
