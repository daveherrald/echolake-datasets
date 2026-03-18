# T1550.002-2: Pass the Hash — CrackMapExec Pass the Hash

## Technique Context

Pass the Hash (T1550.002) enables authentication to remote services using a captured NTLM hash. CrackMapExec (CME) is a post-exploitation framework widely used for network reconnaissance and lateral movement via Pass the Hash against SMB, WinRM, and other Windows protocols. Unlike Mimikatz, CrackMapExec is a network-oriented tool that authenticates to remote systems rather than manipulating local token state.

## What This Dataset Contains

The dataset records the execution of CrackMapExec from a pre-staged binary at `C:\CrackMapExecWin\crackmapexec.exe`. The full attack command is captured in both Security 4688 and Sysmon EID 1:

> `"cmd.exe" /c C:\CrackMapExecWin\crackmapexec.exe %userdnsdomain% -u Administrator -H cc36cf7a8514893efccd3324464tkg1a -x whoami`

This targets the domain (`%userdnsdomain%` = `acme.local`), authenticates as Administrator with an NTLM hash, and attempts remote `whoami` execution. The Sysmon EID 1 record tags this as `technique_id=T1059.003` (Windows Command Shell). The cmd.exe process exits with status `0x1` (general failure), indicating CrackMapExec ran but did not succeed — consistent with the hash being a test value and the target domain not responding as expected in this isolated environment.

A `whoami.exe` process creation appears in both Sysmon and Security logs — this is the ART framework identity pre-check, not output from CrackMapExec's remote execution attempt. Two Sysmon EID 10 (ProcessAccess) events record PowerShell opening both `whoami.exe` and `cmd.exe` with `GrantedAccess: 0x1FFFFF`, consistent with the ART test framework monitoring child processes. Sysmon EID 7 image loads show the standard PowerShell .NET CLR and Defender DLL load sequence across 18 events.

The PowerShell log contains 34 events: two `Set-ExecutionPolicy Bypass` invocations (ART test framework boilerplate) and extensive `PSMessageDetails`/`ErrorCategory_Message` script block fragments. There are no script blocks specific to CrackMapExec because it was invoked as a pre-compiled binary from cmd.exe.

## What This Dataset Does Not Contain (and Why)

There are no successful network authentication events, no SMB logon events (4624 with LogonType 3), and no lateral movement activity. The hash supplied (`cc36cf7a8514893efccd3324464tkg1a`) is a test/placeholder value, and CrackMapExec's exit code of `0x1` indicates the connection or authentication did not succeed. There are no Kerberos events because CrackMapExec uses NTLM. There are no network connection events in Sysmon because CrackMapExec's binary-level networking did not trigger the Sysmon network filter, or the connection attempt failed before completion. The Sysmon ProcessCreate filter did not capture `crackmapexec.exe` itself because it is not in the include-mode LOLBin list — only the parent `cmd.exe` was captured via Security 4688.

## Assessment

This dataset captures a CrackMapExec Pass the Hash attempt with full command-line visibility, including the target domain, username, NTLM hash, and remote command. CrackMapExec ran (unlike the Mimikatz test where the binary was blocked outright) but exited with a failure code, likely because the hash is synthetic. The dataset is valuable for building and testing detections against the CrackMapExec command-line signature pattern. No lateral movement was observed.

## Detection Opportunities Present in This Data

- **Security 4688 / Sysmon EID 1 command line**: The string `crackmapexec.exe` combined with `-H` and a 32-character hex string is a high-confidence indicator. The `-x whoami` remote execution flag further narrows the intent.
- **Binary path `C:\CrackMapExecWin\`**: A non-standard installation directory for a known offensive tool is detectable via file path rules.
- **Parent-child chain**: `powershell.exe` → `cmd.exe` → `crackmapexec.exe` invocation pattern; the cmd.exe command line contains the full attack syntax.
- **Sysmon EID 10 GrantedAccess 0x1FFFFF**: PowerShell with full process access to child processes is anomalous in a normal workstation context.
- **Process exit code 0x1 from cmd.exe**: When combined with the suspicious command line, a non-zero exit suggests a failed attack attempt rather than a configuration error.
