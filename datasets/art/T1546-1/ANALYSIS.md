# T1546-1: Event Triggered Execution — Persistence with Custom AutodialDLL

## Technique Context

T1546 (Event Triggered Execution) covers persistence mechanisms that hijack Windows subsystems so that attacker code runs automatically when specific system events occur. The AutodialDLL technique exploits the Windows Sockets 2 (WinSock2) autodial feature: the registry key `HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\AutodialDLL` normally points to `rasadhlp.dll`, and Windows loads this DLL when any network connection is initiated. By replacing it with an attacker-controlled DLL, the attacker achieves code execution on every subsequent network connection, under any process that makes network calls. This is a low-prevalence, high-impact persistence mechanism. Defenders monitor for modifications to this specific registry value.

## What This Dataset Contains

The attack succeeds and the key evidence is present across Sysmon and Security channels.

**Sysmon EID=1 (ProcessCreate):** A child PowerShell is spawned with the attack command visible in its command line:
`"powershell.exe" & {Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters -Name AutodialDLL -Value C:\AtomicRedTeam\atomics\T1546\bin\AltWinSock2DLL.dll}`

**Sysmon EID=13 (RegistryValueSet):** The write is captured directly:
- `Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- `TargetObject: HKLM\System\CurrentControlSet\Services\WinSock2\Parameters\AutodialDLL`
- `Details: C:\AtomicRedTeam\atomics\T1546\bin\AltWinSock2DLL.dll`

**Security 4688:** The child PowerShell process creation with the full `Set-ItemProperty` command line is logged.

**Sysmon EID=3 (NetworkConnect):** A network connection from `MpDefenderCoreService.exe` (Windows Defender) to an external address is recorded, attributed to `technique_id=T1036,technique_name=Masquerading`. This connection occurred after the DLL was planted, but there is no Sysmon EID=7 confirming `AltWinSock2DLL.dll` was actually loaded — the planted DLL was not loaded during the collection window.

## What This Dataset Does Not Contain

- No Sysmon EID=7 (ImageLoad) for `AltWinSock2DLL.dll` — the DLL is registered in the registry but was not loaded during the collection window (no network-initiating process triggered the autodial path after the write).
- No Security 4657 (Registry value modification) — object access auditing on registry keys is not enabled in the audit policy.
- No verification that the DLL exists on disk. The attack script plants the registry value pointing to `C:\AtomicRedTeam\atomics\T1546\bin\AltWinSock2DLL.dll`, but no Sysmon EID=11 records the DLL file being created; it was presumably pre-staged.
- The PowerShell channel contains only standard test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy fragments) — the `Set-ItemProperty` command ran in the child PowerShell process captured by Sysmon EID=1, not logged again as a separate 4104.

## Assessment

This is a useful dataset for registry-based persistence detection. The Sysmon EID=13 event is the primary detection artifact and it is clean and complete. The child PowerShell command line in Sysmon EID=1 provides a redundant, high-fidelity signal. The main gap — no DLL load confirmation — means the dataset does not demonstrate post-persistence trigger behavior, but for detection of the persistence installation itself, the data is sufficient. Adding a step that makes a network connection after planting the DLL (to capture EID=7 for the malicious DLL loading in a real process) would make this dataset significantly stronger for detecting the technique's execution phase.

## Detection Opportunities Present in This Data

1. **Sysmon EID=13 — write to `HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\AutodialDLL`**: Any modification to this value is suspicious. The legitimate value is `rasadhlp.dll`; any other path — especially outside `System32` — is an immediate indicator.
2. **Sysmon EID=1 — PowerShell command line containing `Set-ItemProperty` targeting WinSock2 registry paths**: Correlating the process create with the registry write confirms the source of the modification.
3. **Security 4688 — PowerShell child process with `Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters`**: The `AutodialDLL` value name in the command line is highly specific.
4. **Baseline monitoring for AutodialDLL value**: The legitimate value (`rasadhlp.dll`) changes extremely rarely. A change detection rule (alerting on any deviation from the baseline) over this single registry value has near-zero false positive risk.
5. **Sysmon EID=7 — unsigned DLL loaded from a non-system path by a process making network connections**: When the DLL is eventually triggered, any process loading a DLL from `C:\AtomicRedTeam\` (or equivalent attacker-controlled path) during network activity would be a strong runtime signal.
