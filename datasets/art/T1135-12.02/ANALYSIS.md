# T1135-12: Network Share Discovery — Enumerate All Network Shares with Snaffler

## Technique Context

Network Share Discovery (T1135) is a foundational reconnaissance technique in which adversaries enumerate accessible file shares across a Windows network to identify sensitive data, credentials, configuration files, and lateral movement opportunities. Snaffler is a purpose-built tool for this task: it automatically connects to domain-joined hosts, discovers their shares, crawls directory structures, and identifies interesting files based on a rich ruleset that flags credentials, keys, configuration files, and similar sensitive content. Security teams classify Snaffler as a dual-use tool, appearing in both red team assessments and real intrusions; its network footprint — rapid sequential SMB connections to multiple hosts — is a characteristic detection opportunity. When Defender is enabled, Snaffler's known binary signatures typically trigger immediate blocking.

## What This Dataset Contains

With Windows Defender disabled, this dataset captures the full Snaffler execution chain from a domain-joined Windows 11 workstation (ACME-WS06.acme.local).

**Process execution chain:** The dataset's defended counterpart described a multi-layer invocation: PowerShell → cmd.exe → PowerShell (base64-encoded) → cmd.exe → Snaffler.exe, with the decoded command `cmd /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\Snaffler.exe" -a -o "$env:temp\T1135SnafflerOutput.txt"`. The `-a` flag enables all Snaffler modules, and `-o` directs output to `C:\Windows\TEMP\T1135SnafflerOutput.txt`. Security EID 4688 events here capture the PowerShell launch chain including the base64-encoded PowerShell command.

**PowerShell test framework:** 118 PowerShell events are present (116 EID 4104, 2 EID 4103). The EID 4103 events confirm execution policy bypass and the Write-Host "DONE" completion marker, indicating the test framework ran through to its end. This is a meaningful difference from the defended run (48 PowerShell events), where Defender cut execution short.

**Process execution evidence:** Sysmon EID 1 records two `whoami.exe` executions (PIDs 18092 and 18428) spawned from the PowerShell process (PID 17660). The EID 4688 security events independently record both, confirming command-line auditing captured them. The Snaffler.exe process itself and the intermediate cmd.exe and encoded-PowerShell stages are not represented in the Sysmon EID 1 samples, consistent with the include-mode Sysmon configuration not matching the Snaffler binary path.

**DLL loading:** Sysmon EID 7 records nine image loads into the PowerShell process, covering the .NET CLR stack (`mscoree.dll`, `clr.dll`, `mscoreei.dll`, `NativeImages/mscorlib.ni.dll`, `clrjit.dll`), PowerShell-specific assemblies, `urlmon.dll`, and Windows Defender integration DLLs (`MpOAV.dll`, `MpClient.dll`).

**Named pipe:** Sysmon EID 17 records the PowerShell host pipe `\PSHost.134182391109263...17660.DefaultAppDomain.powershell`.

**File access:** Sysmon EID 11 records a single file access: powershell.exe touching `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive`. This is a normal PowerShell profile artifact.

Compared to the defended run (53 Sysmon, 23 Security, 48 PowerShell, plus System and WMI events), this undefended dataset has fewer events (15 Sysmon, 2 Security, 118 PowerShell) but a completed test framework. The defended run produced more Sysmon and Security events because Defender's intervention generated block and WMI activity; here, the execution completed without that defensive overhead.

## What This Dataset Does Not Contain

**Snaffler network activity:** The most valuable detection data for this technique — sequential SMB connections to domain hosts, Sysmon EID 3 network connections, DNS queries for host resolution, and file access events on remote shares — is absent. The Sysmon-modular include-mode configuration does not appear to have captured Snaffler's network behavior. Whether Snaffler completed its enumeration successfully or encountered errors cannot be confirmed from this dataset alone.

**Output file creation:** Snaffler was invoked with `-o "$env:temp\T1135SnafflerOutput.txt"`, which would write discovered findings to `C:\Windows\TEMP\T1135SnafflerOutput.txt`. No Sysmon EID 11 event for this file appears, suggesting either Snaffler did not find anything to write, the file was created outside the logging window, or the configuration did not capture it.

**Snaffler.exe process creation:** No EID 1 event for `Snaffler.exe` appears in the Sysmon samples. The tool ran from `C:\AtomicRedTeam\...\ExternalPayloads\Snaffler.exe`, a path not typically in the Sysmon include-mode filter.

**Authentication events:** No Security EID 4624 (logon) or EID 4648 (explicit credential logon) events from Snaffler's share access attempts appear in the dataset. If Snaffler successfully connected to remote shares, those authentications would be recorded, but they are not present here.

## Assessment

This dataset's detection value is limited compared to what a successful Snaffler run would ideally produce. The most actionable evidence available is the Security EID 4688 process creation chain showing the multi-layer PowerShell invocation with the base64-encoded payload that decodes to Snaffler's command line. If command-line auditing is enabled, the encoded command and Snaffler's path and arguments are visible in the process chain.

The contrast with the defended variant is instructive: in the defended run, Defender's blocking generated richer system-level telemetry (WMI events, higher Sysmon counts), while this undefended run completed with fewer events but confirmed the test framework ran through successfully. For a dataset intended to test detection of Snaffler itself, this collection would benefit from richer Sysmon configuration that captures non-LOLBin process creation and network connections from third-party tools.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** PowerShell spawning cmd.exe with a base64-encoded `-EncodedCommand` payload; the decoded content references `Snaffler.exe` with `-a` and `-o` flags
- **Security EID 4688 process chain:** The whoami.exe executions from PowerShell running as SYSTEM with `IntegrityLevel: System` are anomalous for normal workstation use
- **PowerShell EID 4104:** Base64 decode of the encoded command would reveal `Snaffler.exe -a -o` in retrospective analysis of script block logs
- **File system hunting:** A post-execution hunt for `C:\Windows\TEMP\T1135SnafflerOutput.txt` or similar named output files would reveal whether Snaffler successfully enumerated shares
- **Hash-based detection:** Sysmon EID 7 captures the PowerShell binary hashes; the Snaffler binary hash could be added to threat intelligence lookups if endpoint tooling logs its load
