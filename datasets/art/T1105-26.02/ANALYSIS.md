# T1105-26: Ingress Tool Transfer — Download a file using wscript

## Technique Context

T1105 (Ingress Tool Transfer) encompasses file downloads from external sources into a target environment. This test uses `wscript.exe`—the Windows Script Host interpreter—to execute a VBScript file that downloads content from a remote URL. The appeal for adversaries is similar to other LOLBin approaches: `wscript.exe` is a signed Microsoft binary present on all Windows systems, it can make HTTP requests via COM objects (specifically `MSXML2.XMLHTTP` or `WinHttp.WinHttpRequest`), and it may be overlooked by controls focused on PowerShell or executable downloads.

This test executes a VBScript at `C:\AtomicRedTeam\atomics\T1105\src\T1105-download-file.vbs` that downloads a file from `raw.githubusercontent.com`, placing it in `C:\Windows\Temp\`.

## What This Dataset Contains

This dataset was collected on ACME-WS06, a Windows 11 Enterprise domain workstation with Microsoft Defender disabled, allowing the download to complete without interference.

**Process Chain (Sysmon EID 1 / Security EID 4688):**

The execution begins with the ART PowerShell test framework (PID 4316) spawning `cmd.exe` (PID 5704) with:

```
"cmd.exe" /c wscript.exe "C:\AtomicRedTeam\atomics\T1105\src\T1105-download-file.vbs"
```

Sysmon tags this `cmd.exe` invocation as `technique_id=T1059.003`. Immediately, `cmd.exe` (PID 5704) spawns `wscript.exe` (PID 1132), tagged `technique_id=T1202` (Indirect Command Execution), with:

```
wscript.exe  "C:\AtomicRedTeam\atomics\T1105\src\T1105-download-file.vbs"
```

**DNS Query (Sysmon EID 22):**

Sysmon captured a DNS resolution for `raw.githubusercontent.com` at 23:45:31.121, returning four IPv4-mapped IPv6 addresses: `::ffff:185.199.110.133`, `::ffff:185.199.111.133`, `::ffff:185.199.108.133`, `::ffff:185.199.109.133`. This is the GitHub CDN resolving GitHub's content delivery network. The querying process appears as `<unknown process>` with PID 1132—this is a known Sysmon limitation with DNS resolution attribution when the query is initiated through a COM/WinSock path used by wscript.exe. The PID matches the wscript.exe instance.

**File Creation (Sysmon EID 11):**

`wscript.exe` (PID 1132) creates `C:\Windows\Temp\Atomic-License.txt` at 23:45:34.955, confirming the download completed. Sysmon tags this event `technique_id=T1574.010` (Services File Permissions Weakness) based on the target path—this tag reflects the ruleset's sensitivity to writes under `C:\Windows\Temp\` rather than an actual DLL hijack.

**Image Loads (Sysmon EID 7):**

Thirteen DLL load events capture the PowerShell .NET runtime initialization for PID 4316: `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `System.Management.Automation.ni.dll`, `MpOAV.dll`, `MpClient.dll`, `urlmon.dll`, and others. The load of `urlmon.dll` into the PowerShell process reflects the test framework itself, not wscript's download. The download mechanism in wscript would involve `jscript.dll` or `vbscript.dll` loads, but wscript's DLL loads are not captured in the sample set.

**Process Access (Sysmon EID 10):**

PowerShell (PID 4316) opens `whoami.exe` (PID 4900 and 4788) and `cmd.exe` (PID 5704) with `GrantedAccess: 0x1FFFFF`—the standard ART test framework pattern for waiting on child processes.

**Named Pipe (Sysmon EID 17):**

The PSHost pipe `\PSHost.134180055289722388.4316.DefaultAppDomain.powershell` is created by PID 4316.

**PowerShell Script Block Logging (EID 4104):**

93 script block events capture the ART test framework execution, consistent with other T1105 tests in this series.

## What This Dataset Does Not Contain

No network connection event (Sysmon EID 3) is present for the outbound HTTP request made by wscript.exe. Sysmon network monitoring did not capture the TCP connection to the GitHub CDN, only the DNS resolution. The absence of EID 3 for wscript.exe is notable—wscript performs its HTTP via COM interfaces that may not be instrumented the same way as direct socket calls.

The VBScript contents are not logged. Script block logging covers PowerShell (EID 4104) but has no equivalent for VBScript; you cannot see the download URL or the HTTP request logic directly in this dataset. Registry access by wscript.exe is not captured.

The cleanup that removes the downloaded file is not visible, and there is no error or failure telemetry—the download succeeded silently.

## Assessment

This dataset demonstrates a complete wscript-based file download with a confirmed file creation artifact. The combination of DNS resolution for `raw.githubusercontent.com` (EID 22) and file creation in `C:\Windows\Temp\` by `wscript.exe` (EID 11) provides coherent end-to-end evidence. The process chain—PowerShell spawning cmd.exe spawning wscript.exe to run a `.vbs` file—is unusual in enterprise environments and captures several independently detectable behaviors.

Compared to the defended variant, this undefended dataset has similar Sysmon coverage (23 events vs. ~18 defended baseline for comparable tests) with the same Security event count of 4. The key difference is that in the defended variant, Defender would block the download or quarantine the target file, producing additional Security 4688 events for MpCmdRun.exe and altering or preventing the EID 11 file creation. Here, the download completes cleanly.

## Detection Opportunities Present in This Data

**wscript.exe network activity (EID 22):** A DNS query to `raw.githubusercontent.com` attributed to `wscript.exe` is a strong indicator. Legitimate wscript use in enterprise environments rarely involves public internet DNS resolution. The combination of wscript spawned by cmd.exe spawned by PowerShell with an external DNS query should be treated as high-confidence.

**Parent-child chain (EID 1):** `powershell.exe → cmd.exe → wscript.exe <.vbs file>` is an unusual process lineage. The `.vbs` file path under `C:\AtomicRedTeam\` is obviously test-specific, but in a real scenario any `.vbs` file downloaded or placed in a writable directory and executed via this chain warrants investigation.

**File write to %TEMP% by wscript.exe (EID 11):** `wscript.exe` writing to `C:\Windows\Temp\` is atypical. Standard use of Windows Script Host does not involve writing files to system temp directories.

**Sysmon rule tag:** cmd.exe is tagged `technique_id=T1059.003` and wscript.exe is tagged `technique_id=T1202` (Indirect Command Execution), providing dual classification from the built-in ruleset.
