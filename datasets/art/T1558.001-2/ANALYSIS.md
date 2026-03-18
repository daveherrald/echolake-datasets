# T1558.001-2: Golden Ticket — Crafting Active Directory golden tickets with Rubeus

## Technique Context

T1558.001 (Golden Ticket) can also be performed with Rubeus, a C# Kerberos toolkit that implements golden ticket forging without the mimikatz dependency. Rubeus's `golden` command accepts the KRBTGT AES256 key, username, and DC FQDN to produce a `.kirbi` file that can be imported with Pass-the-Ticket (`/ptt`). Because Rubeus is a compiled .NET assembly, it is often injected or run via reflective loading to avoid on-disk detection.

## What This Dataset Contains

The dataset spans seven seconds on 2026-03-14 on ACME-WS02 (Windows 11 Enterprise, domain acme.local). This test generated substantially more forensic content than the mimikatz golden ticket test.

The EID 4104 script block records the full Rubeus invocation:

```powershell
Remove-Item $env:TEMP\golden.bat -ErrorAction Ignore
Remove-Item $env:TEMP\golden.txt -ErrorAction Ignore
cmd.exe /c "$Env:temp\rubeus.exe" golden /aes256:b7268361386090314acce8d9367e55f55865e7ef8e670fbe4262d6c94098a9e9 \
    /ldap /user:$ENV:username /dc:$($ENV:logonserver.TrimStart('\') + "." + "$ENV:userdnsdomain") \
    /printcmd /outfile:golden
```

The AES256 key `b7268361386090314acce8d9367e55f55865e7ef8e670fbe4262d6c94098a9e9` is the test KRBTGT hash used by the ART test. EID 4103 records cleanup errors (`Cannot find path 'C:\Windows\TEMP\golden.bat'`) — confirming the cleanup ran before the test artifacts existed.

Sysmon events include:
- **EID 1**: `whoami.exe` (T1033), `powershell.exe` (T1134 — Access Token Manipulation), `cmd.exe` (T1059.003), `runas.exe` (T1134), and another `cmd.exe` — this sequence reflects Rubeus's execution chain
- **EID 7**: DLL loads including Defender's `MsMpEng` platform DLLs (cloud lookup during Rubeus execution)
- **EID 10**: Cross-process access (T1055.001)
- **EID 11**: `C:\Windows\Temp\golden.bat` file written by PowerShell — the Rubeus output batch file
- **EID 17**: Named PSHost pipes

Security events include EID 4624 (Logon Type 9 — `runas`-style logon with alternate credentials), EID 4627 (group membership), EID 4634 (logoff), EID 4672 (special privileges for SYSTEM). The Type 9 logon is significant — it indicates Rubeus or its execution chain used `CreateProcessWithLogonW` or `runas.exe` to create a new logon session.

## What This Dataset Does Not Contain (and Why)

**No Kerberos ticket events on the domain controller side.** The Rubeus golden ticket was forged locally — no TGT request was sent to the DC during forging. If the ticket were used to access resources, EID 4768/4769 on the DC would be relevant, but resource access was not simulated.

**No EID 4769 from the workstation.** The test used `/printcmd` and `/outfile` to produce the golden ticket file but did not inject it into the current logon session with `/ptt`.

**No LSASS access.** Rubeus's `golden` command constructs the ticket from supplied parameters (AES256 key, username, domain) — it does not read LSASS. The AES256 key was hardcoded in the test.

## Assessment

This is the richest dataset across the T1558.001 tests. Unlike T1558.001-1 (mimikatz, fully blocked by Defender), Rubeus partially executed — the `golden.bat` file was written to `C:\Windows\Temp\` (Sysmon EID 11), the EID 4104 script block reveals the full command including the AES256 key, and the Security log shows a Type 9 logon. The test framework invoked `runas.exe` to execute Rubeus (Sysmon EID 1 with T1134 tag), which explains the logon type and the special privilege assignment.

## Detection Opportunities Present in This Data

- **EID 4104**: The complete Rubeus command line including the AES256 key is visible in script block logging — `/aes256:` followed by a 64-character hex string is directly signable.
- **EID 11 (Sysmon)**: `golden.bat` file created in `C:\Windows\Temp\` by PowerShell is a specific artifact. Any file with `golden` in the name under `Temp` warrants investigation.
- **EID 1 (Sysmon)**: `runas.exe` spawned from PowerShell under SYSTEM (tagged T1134) is an unusual invocation pattern — runas.exe is rarely run from SYSTEM to spawn another SYSTEM process.
- **EID 4624 (Security)**: Logon Type 9 (`NewCredentials` logon) from SYSTEM following PowerShell execution is anomalous and correlates with the Rubeus `runas` invocation.
- **EID 4672**: Special privileges assigned immediately after a Type 9 logon in a non-interactive session is worth flagging.
- **String matching**: The `/aes256:` and `/ldap` flags in Rubeus command lines are specific to Kerberos ticket operations and rarely appear in legitimate process invocations.
