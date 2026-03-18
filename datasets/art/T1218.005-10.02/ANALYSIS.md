# T1218.005-10: Mshta — Mshta Used to Execute PowerShell

## Technique Context

T1218.005 (Mshta) covers abusing `mshta.exe`, the Microsoft HTML Application Host, to execute arbitrary code. Test 10 uses the `about:` protocol URI to embed inline HTA content with VBScript directly in the mshta.exe command line argument — no external file or network connection is required. The inline VBScript uses `Wscript.Shell.Run` to launch PowerShell with a specific command, making this a compact, fileless technique variant.

The attack format is: `mshta.exe "about:<hta:application><script language="VBScript">Close(Execute("CreateObject(""Wscript.Shell"").Run%20""powershell.exe%20-nop%20-Command%20...""))</script>"`. The `about:` protocol causes mshta.exe to interpret the URI content as inline HTA, executing the embedded VBScript. This variant leaves no HTA file on disk — the entire script payload is contained within the process command line argument.

## What This Dataset Contains

The dataset spans 4 seconds (2026-03-17T16:50:36Z to 16:50:40Z) across 171 total events: 99 PowerShell, 31 Security, 40 Sysmon, 1 Application.

**Complete four-step execution chain (Security EID 4688):** All process creation events in the full chain are captured:

1. `cmd.exe` (PID 0x40f4) spawned by PowerShell (PID 0x3cec) with:
   ```
   "cmd.exe" /c mshta.exe "about:<hta:application><script language="VBScript">Close(Execute("CreateObject(""Wscript.Shell"").Run%20""powershell.exe%20-nop%20-Command%20Write-Host%20Hello,%20MSHTA!;Start-Sleep%20-Seconds%205""))</script>'"
   ```

2. `mshta.exe` (PID 0x4428) spawned by `cmd.exe` (PID 0x40f4) with the same `about:` inline VBScript argument.

3. `powershell.exe` (PID 0x4134) spawned by `mshta.exe` (PID 0x4428) with:
   ```
   "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -Command Write-Host Hello, MSHTA!;Start-Sleep -Seconds 5
   ```

The mshta.exe process (0x4428) is directly observable as a parent in the Security EID 4688 for the PowerShell child. The full VBScript payload, including URL-encoded spaces (`%20`) and the PowerShell command, is visible in the mshta.exe command line.

**WMI Provider Host (Sysmon EID 1, Security EID 4688):** `wmiprvse.exe` (PID 18176 / 0x4700) spawned from `svchost.exe` as NETWORK SERVICE. This is a WMI provider activation triggered by test framework monitoring — consistent with the WMI process trace subscription pattern seen in T1218.005-2.

**Cmd.exe from test framework PowerShell (Sysmon EID 1):** A second `cmd.exe` (PID 15468) spawned by the test framework PowerShell (PID 15596, labeled `powershell` in parent command line). The command is `"cmd.exe" /c` with truncated content — this is the cleanup phase. The full cleanup block in PS EID 4104 confirms this.

**Security EID 4799 — Group membership enumeration (19 events):** The `powershell.exe` process spawned by mshta.exe executed `Get-LocalGroupMember` or equivalent enumeration across multiple local groups: `Access Control Assistance Operators` (S-1-5-32-579), `Administrators` (S-1-5-32-544), `Backup Operators` (S-1-5-32-551), and others. These 19 events confirm the PowerShell payload ran and performed discovery. The group membership enumeration matches the Cribl.exe process's routine query (EID 4799 is triggered by Cribl Edge's internal checks) as well as mshta-spawned PowerShell activity.

**Security EID 4798 — User local group membership enumeration (5 events):** The `Administrator` account (S-1-5-21-...-500) had its group memberships enumerated by a SYSTEM process. This is part of the same local reconnaissance that generated the 4799 events.

**Application EID 15:** "Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON" — Defender status reporting, routine background event.

## What This Dataset Does Not Contain

There are no Sysmon EID 7 image load events for VBScript-related DLLs (`vbscript.dll`, `wshom.ocx`, `scrrun.dll`) in the sample set. The defended dataset captures these DLL loads into mshta.exe, confirming they occur — but in the undefended run, these 40 Sysmon events are dominated by the .NET runtime DLL loads into the PowerShell processes, leaving the mshta.exe-specific DLL loads outside the sample window.

## Assessment

This is the clearest successful mshta execution in this dataset series. The complete chain — PowerShell → cmd.exe → mshta.exe → powershell.exe — is documented with full command lines at every hop. The VBScript payload is entirely contained within the `mshta.exe` command line argument, making this a fileless execution variant. The Security EID 4688 records provide unambiguous evidence with parent-child PID relationships confirmed across all four process hops.

Comparing with the defended variant (42 Sysmon, 13 Security, 36 PowerShell events): the defended dataset similarly captures the full chain. In the defended run, the Sysmon EID 7 events for `vbscript.dll`, `wshom.ocx`, and `scrrun.dll` loading into mshta.exe are present — these DLL loads are the signature of VBScript execution within mshta.exe and are absent from the undefended sample set due to sample prioritization. The undefended run generates 31 Security events (vs. 13 defended) primarily because of the 19 EID 4799 group enumeration events generated by the mshta-spawned PowerShell.

## Detection Opportunities Present in This Data

**`mshta.exe` with `about:` inline HTA content (Security EID 4688, Sysmon EID 1):** The `about:` protocol used as an mshta.exe argument is a documented technique variant that avoids writing any HTA file. The `<hta:application>` tag embedded in the `about:` URI is the distinguishing indicator — legitimate mshta.exe usage with `about:` is effectively nonexistent.

**`mshta.exe` spawning `powershell.exe` (Security EID 4688):** The parent-child chain mshta.exe → powershell.exe is the behavioral signature of this technique class. The spawned PowerShell's command line (`-nop -Command Write-Host Hello, MSHTA!;Start-Sleep -Seconds 5`) is trivial in this test, but in a real attack it would contain the actual post-compromise payload.

**URL-encoded content in mshta.exe command line (Security EID 4688):** The `%20` URL encoding within the `about:` HTA content indicates scripted command construction. While standard for URL encoding, its presence in a command-line argument to mshta.exe alongside `Wscript.Shell.Run` is a reliable indicator of malicious content.

**`cmd.exe` command line containing `mshta.exe "about:` (Security EID 4688, Sysmon EID 1):** The launch pattern `cmd.exe /c mshta.exe "about:..."` is a well-documented indicator. The `cmd.exe` → `mshta.exe` relationship with `about:` content is distinct from legitimate mshta usage.

**EID 4799/4798 group enumeration bursts following mshta.exe execution (Security):** Twenty-four combined group enumeration events (4799 + 4798) appearing shortly after an mshta.exe execution indicate that the spawned payload performed local reconnaissance. Correlating these events back through the process ancestry to mshta.exe identifies the discovery activity as originating from the LOLBin execution path.
