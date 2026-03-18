# T1220-1: XSL Script Processing — MSXSL Bypass Using Local Files

## Technique Context

T1220 (XSL Script Processing) exploits XSLT processors to execute arbitrary code embedded in XSL stylesheets. The technique is attractive to attackers because XSLT is a legitimate XML transformation technology, and the tool used here — `msxsl.exe` — is a Microsoft-signed command-line utility for processing XML with XSL stylesheets.

`msxsl.exe` accepts an XML input file and an XSL stylesheet, then processes the stylesheet. XSL stylesheets can embed JScript or VBScript in `<msxsl:script>` elements, which `msxsl.exe` will execute as part of the transformation. The result: arbitrary script code runs under a signed Microsoft binary, potentially bypassing application whitelisting controls that do not account for XSLT scripting.

This test uses local files — both the XML input and the XSL stylesheet are on disk:

```
msxsl.exe "C:\AtomicRedTeam\atomics\T1220\src\msxslxmlfile.xml"
           "C:\AtomicRedTeam\atomics\T1220\src\msxslscript.xsl"
```

The XSL file (`msxslscript.xsl`) contains embedded script code that runs when the transformation executes.

## What This Dataset Contains

The key evidence is the command line invoking `msxsl.exe`, captured in both the Security and Sysmon channels.

**Security EID 4688** captures `cmd.exe` (PID 0x41d4) spawned by `powershell.exe` (PID 0x3bdc) with command line: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\msxsl.exe" "C:\AtomicRedTeam\atomics\T1220\src\msxslxmlfile.xml" "C:\AtomicRedTeam\atomics\T1220\src\msxslscript.xsl"`. A second EID 4688 shows the cleanup `cmd.exe` running `del "C:\AtomicRedTeam\atomics\..\ExternalPayloads\msxsl.exe"`.

**Sysmon EID 1** independently captures the `cmd.exe` process with full hash data:
- SHA1: `94BDAEB55589339BAED714F681B4690109EBF7FE`
- MD5: `7620F0BC3228FE019A6BD8C593C1D856`
- SHA256: `A6E3B3B22B7FE8CE2C9245816126723EAA13F43B9F591883E59959A2D409426A`

The parent chain is: `powershell` (PID 15324) → `cmd.exe` (PID 16852) → (msxsl.exe invoked).

**Sysmon EID 10 (ProcessAccess)** shows `powershell.exe` accessing `whoami.exe` and `cmd.exe` with `GrantedAccess: 0x1FFFFF` — the ART test framework pattern.

**Sysmon EID 7** (9 events) records `.NET` runtime and Defender DLLs loading into `powershell.exe` (PID 15324). No `msxsl.exe`-specific DLL loads appear in the sample set.

The defended analysis for this test documents that the `cmd.exe` exited with status `0x1`, indicating `msxsl.exe` failed. However, with Defender disabled, the failure here is likely that `msxsl.exe` encountered a file access or compatibility issue, not a security block — the tool executed but returned an error. The cleanup `del` command executing afterward confirms the ART test framework ran past the initial invocation.

Total event counts: 0 Application, 107 PowerShell, 4 Security (EID 4688), 19 Sysmon.

The undefended and defended datasets have nearly identical event counts (19 vs. 36 Sysmon). With Defender disabled, the MSXSL invocation should have proceeded without interference, yet the similar failure pattern suggests the issue was environmental rather than security-related.

## What This Dataset Does Not Contain

No **Sysmon EID 1** event for `msxsl.exe` itself appears. The Sysmon configuration's include rules do not match `msxsl.exe` by name, so while `cmd.exe` was logged, the actual `msxsl.exe` process creation is not directly captured.

No child processes spawned from `msxsl.exe` appear. If the XSL script successfully executed (e.g., launching `calc.exe` or another payload), those events would show as `msxsl.exe`-parented process creations — but they are absent, consistent with the `cmd.exe` exit code of `0x1` indicating failure.

No **Sysmon EID 7** events for `jscript.dll`, `vbscript.dll`, or `scrobj.dll` loading into `msxsl.exe` appear. These DLL loads would confirm that the XSL scripting engine was invoked, which is the mechanism of code execution in this technique.

The **PowerShell channel** (107 events) is test framework boilerplate only.

## Assessment

This dataset documents a T1220 MSXSL attempt with command line evidence fully preserved, but without evidence of successful script execution. The `cmd.exe` carrying the msxsl invocation is visible in both Security and Sysmon with complete command lines and hashes. For detection engineering, the key value is in the command line pattern: `msxsl.exe` invoked with two file arguments where one is a `.xsl` file and the `msxsl.exe` binary itself is located outside of standard system paths (`ExternalPayloads\` rather than `C:\Windows\System32\`). The non-standard location of `msxsl.exe` is itself an indicator, since the tool does not ship with Windows and must be downloaded/staged.

## Detection Opportunities Present in This Data

The following behavioral observables are directly present in the event records:

- **Security EID 4688** and **Sysmon EID 1** both capture the `msxsl.exe` invocation via `cmd.exe` with the full XML and XSL file paths. Any command line containing `msxsl.exe` followed by two file arguments where one ends in `.xsl` is a high-fidelity T1220 indicator.
- The `msxsl.exe` binary is located at `C:\AtomicRedTeam\atomics\..\ExternalPayloads\msxsl.exe` — outside of standard Windows system directories. `msxsl.exe` invoked from non-standard paths is more suspicious than from `C:\Windows\System32\`, since legitimate MSXSL usage would typically be from a known, controlled path.
- **Security EID 4688** shows the parent `powershell.exe` → `cmd.exe` chain with the MSXSL invocation. An automated scripting engine spawning `cmd.exe` that in turn invokes XSLT processing is consistent with T1220 tradecraft.
- The XSL file path `C:\AtomicRedTeam\atomics\T1220\src\msxslscript.xsl` is from an ART staging directory. In real attacks, the equivalent would be a user-writable temp directory or an attacker-controlled file path. Detection logic targeting `.xsl` files from non-standard directories in `msxsl.exe` invocations is directly applicable.
- **Sysmon EID 7** in a successful execution would show `jscript.dll` or `msxml6.dll` loading into `msxsl.exe`. If your dataset extends to successful MSXSL script execution, the absence of these DLL loads here helps distinguish partial from complete T1220 telemetry.
