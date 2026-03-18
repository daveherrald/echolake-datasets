# T1558.001-2: Steal or Forge Kerberos Tickets: Golden Ticket — Crafting Active Directory Golden Tickets with Rubeus

## Technique Context

MITRE ATT&CK T1558.001 (Golden Ticket) can also be performed with Rubeus, a C# Kerberos toolkit that implements golden ticket forging without the Mimikatz dependency. Rubeus's `golden` command accepts the KRBTGT AES256 key, username, and DC FQDN to produce a `.kirbi` file (a Kerberos ticket in the binary format used by Windows). The ticket can then be loaded with `ptt` (Pass-the-Ticket). Because Rubeus is a compiled .NET assembly, it is often loaded reflectively or executed from a temp directory to reduce on-disk exposure.

With Defender disabled, Rubeus executes the full golden ticket forging workflow: compute the ticket, write it to disk as a `.kirbi` file, inject it into a new logon session via `runas /netonly`, and use it to authenticate to SYSVOL.

## What This Dataset Contains

This dataset was captured on ACME-WS06 (Windows 11 Enterprise, domain acme.local) on 2026-03-17 with Defender disabled, spanning approximately 5 seconds. It contains 195 events across four channels: 48 Sysmon, 131 PowerShell, 14 Security, and 2 Application. This is the highest event count among the Kerberos forging tests, reflecting the richer execution chain of the Rubeus approach.

**Command executed (Security EID=4688):**
```
cmd.exe /c "C:\Windows\TEMP\rubeus.exe" golden
  /aes256:b7268361386090314acce8d9367e55f55865e7ef8e670fbe4262d6c94098a9e9
  /ldap /user:ACME-WS06$ /dc: /printcmd /outfile:golden
```
The full Rubeus invocation appears verbatim in Security EID=4688. The AES256 key `b7268361386090314acce8d9367e55f55865e7ef8e670fbe4262d6c94098a9e9` is the test KRBTGT hash. The `/ldap` flag instructs Rubeus to query the domain via LDAP to resolve domain information, `/printcmd` outputs the equivalent Mimikatz command for reference, and `/outfile:golden` writes the ticket to disk.

**Full execution chain (Security EID=4688 and Sysmon EID=1):**

The following process sequence was recorded:
1. `powershell.exe` — the outer test framework process with the full golden ticket script
2. `cmd.exe` — invoking `C:\Windows\TEMP\rubeus.exe golden /aes256:...`
3. `runas.exe` — `"C:\Windows\system32\runas.exe" /netonly /user:fake C:\Windows\TEMP\golden.bat`
4. `svchost.exe -k netsvcs -p -s seclogon` — the Secondary Logon service starting to process the runas request
5. `cmd.exe /c C:\Windows\TEMP\golden.bat` — the batch file executing in the new isolated session
6. `klist purge` — clearing existing Kerberos tickets in the new session
7. `klist` — listing tickets after the golden ticket injection

**Security EID=4624 (Logon event):** A logon type 9 (NewCredentials) event records the `runas /netonly` session creation:
```
Account Name: SYSTEM (NT AUTHORITY)
Logon Type: 9 (NewCredentials — runas /netonly)
Network Account Name: fake
Network Account Domain: ACME-WS06
```
This logon event is the direct artifact of `runas /netonly /user:fake` creating an isolated credential context for the golden ticket injection. It is absent in the defended dataset.

**Security EID=4672 (Special logon):** Special privileges assigned to the new logon — SYSTEM-level privileges for the seclogon-mediated session.

**Security EID=4634 (Logoff):** Logon type 9 session terminated after the batch file completed.

**Security EID=5379 (Credential Manager read):** Credential Manager credentials read by `ACME-WS06$` — a side effect of the new session initialization.

**PowerShell EID=4104:** 118 script block events. The full Rubeus invocation script, the batch file construction logic, and the golden ticket file handling are all captured verbatim.

**Sysmon EID=1 (Process Create):** Nine process creations capturing the full execution chain — the most comprehensive process tree of any test in this series.

**Sysmon EID=10 (Process Access):** Six EID=10 events at `GrantedAccess: 0x1FFFFF`, tagged `T1055.001`.

**Sysmon EID=11 (File Created):** Five file creation events including the Defender scan artifact (`C:\Windows\Temp\01dcb6330c7cb87e`) and the PowerShell startup profile.

**Sysmon EID=17 (Pipe Created):** Three named pipe events from PowerShell console host infrastructure.

## What This Dataset Does Not Contain

**Rubeus.exe in Sysmon EID=1.** Rubeus is invoked by `cmd.exe` via the command line `cmd.exe /c C:\Windows\TEMP\rubeus.exe golden ...`. The Sysmon ProcessCreate filter likely captures the `cmd.exe` wrapper but may not capture `rubeus.exe` unless it matches an include rule. Security EID=4688 records the `cmd.exe` event with the full Rubeus command line in the command-line field.

**The generated .kirbi golden ticket file.** The Rubeus `/outfile:golden` flag writes the ticket to a file named `golden_<timestamp>.kirbi` in the current working directory (`C:\Windows\TEMP\`). This file creation does not appear in the EID=11 Sysmon samples, though the script logic references it — `Get-ChildItem | ? {$_.Name.startswith("golden_")}` identifies the output file. The file was written to `%TEMP%` but not captured in the available Sysmon samples.

**Kerberos EID=4768/4769 on the domain controller.** Golden ticket forging is entirely client-side. The ticket injection (`ptt`) and subsequent SYSVOL access would generate DC-side Kerberos events only if the forged ticket were accepted and used. The test script includes a `dir \\%logonserver%\SYSVOL` step, but whether that succeeded and generated DC events is not visible in this workstation-side telemetry.

**Comparison with the defended variant:** In the defended dataset (sysmon: 38, security: 26, powershell: 60), Defender blocked Rubeus.exe. The defended dataset's higher security event count (26 vs 14 here) reflects additional process lifecycle events from Defender's monitoring. The undefended dataset has fewer security events but more meaningful ones: EID=4624 (logon type 9), EID=4672, and EID=4634 all record the `runas /netonly` session lifecycle — these were absent in the defended run because the session was created as part of Rubeus's execution flow, which Defender interrupted.

## Assessment

This is the richest dataset in the Kerberos forging test group. The complete execution chain — PowerShell constructing a Rubeus golden ticket invocation, `cmd.exe` launching Rubeus, `runas.exe` creating an isolated credential context, `svchost.exe` (seclogon service) processing the request, and `cmd.exe` executing the batch file to inject and use the ticket — is fully recorded across nine Sysmon process creates and ten Security EID=4688 events.

The Security EID=4624 logon type 9 event is particularly valuable: it records the `runas /netonly /user:fake` session creation and provides a direct artifact of the ticket injection technique's execution method.

## Detection Opportunities Present in This Data

**Security EID=4688 — cmd.exe with rubeus.exe golden /aes256: command line:** The full Rubeus invocation including the 64-character AES256 key, `/ldap`, `/printcmd`, and `/outfile:golden` is a precise, high-confidence indicator.

**Security EID=4624 — Logon type 9 (NewCredentials) from SYSTEM:** A `runas /netonly` logon (type 9) originating from SYSTEM context where the network account name is `fake` or similarly implausible is a direct indicator of the golden ticket isolation technique.

**Sysmon EID=1 — klist.exe invocations:** Two `klist` invocations — `klist purge` followed by `klist` — in a batch file context spawned by `runas /netonly` is a characteristic golden ticket validation sequence.

**Sysmon EID=1 — runas.exe /netonly /user:fake with a batch file path:** `runas.exe /netonly` with a non-domain user (`fake`) targeting a batch file in `%TEMP%` is a specific behavioral pattern for Kerberos ticket isolation.

**Security EID=4688 — svchost.exe -k netsvcs -p -s seclogon:** The Secondary Logon service (`seclogon`) starting in direct temporal proximity to a `runas /netonly` invocation that references a golden ticket batch file is a meaningful correlation indicator.

**PowerShell EID=4104 — Rubeus invocation with AES256 key and golden ticket parameters:** The script block captures the full `rubeus.exe golden /aes256:...` command string, including the output file pattern `golden_*.kirbi`.
