# T1562.004-6: Disable or Modify System Firewall — Allow Executable Through Firewall Located in Non-Standard Location

## Technique Context

T1562.004 (Disable or Modify System Firewall) includes creating application-based inbound firewall
rules that permit a specific executable to receive connections regardless of port. Malware and
attacker tooling frequently uses this technique to allow a dropped binary to act as a listener or
accept C2 connections while looking like a benign firewall exception. The key indicator is an
inbound allow rule referencing an executable in a user-writable, non-standard location.

## What This Dataset Contains

The test copied `AtomicTest.exe` from the ART payloads directory to `C:\Users\ACME-WS02$\` and
then ran `netsh advfirewall firewall add rule name="Atomic Test" dir=in action=allow
program=C:\Users\ACME-WS02$\AtomicTest.exe enable=yes`. Executed via PowerShell under
NT AUTHORITY\SYSTEM.

**Sysmon EID 1 — process creation (42 events, 3 process-create):**
- `powershell.exe & {Copy-Item "C:\AtomicRedTeam\atomics\T1562.004\bin\AtomicTest.exe" -Destination "C:\Users\$env:UserName" -Force; netsh advfirewall firewall add rule name="Atomic Test" dir=in action=allow program="C:\Users\$env:UserName\AtomicTest.exe" enable=yes}` (parent: WmiPrvSE.exe)
- `netsh.exe advfirewall firewall add rule "name=Atomic Test" dir=in action=allow program=C:\Users\ACME-WS02$\AtomicTest.exe enable=yes` (child of powershell.exe)
- `whoami.exe`

**Sysmon EID 29 — file executable detected (1 event):**
Sysmon detected `AtomicTest.exe` being written to `C:\Users\ACME-WS02$\AtomicTest.exe` by
`powershell.exe` (Copy-Item):
```
TargetFilename: C:\Users\ACME-WS02$\AtomicTest.exe
Hashes: SHA1=49AE46469FB50A35734EA63BD408912E0C94937D, MD5=F7CE09AFA3032CD10E9DB1F37D71B2BD,
        SHA256=081586DFF9FDB719619AC993B104EA23698CBEB4ECF55E0EF201614BD544E4AD
```

**Sysmon EID 13 — registry value set (2 events):**
- `HKLM\...\FirewallRules\{59CC776A-116B-4098-B5E4-7714C2D4B6AE}` — `v2.32|Action=Allow|Active=TRUE|Dir=In|App=C:\Users\ACME-WS02$\AtomicTest.exe|Name=Atomic Test|`
- `Epoch\Epoch` increment

**Security EID 4688 (12 events):** whoami.exe, powershell.exe, netsh.exe. SYSTEM context.

**PowerShell EID 4104 (37 events):** Two script blocks contain the full test command including
the Copy-Item and netsh invocation. Remaining 35 are ART test framework boilerplate.

## What This Dataset Does Not Contain (and Why)

**No Sysmon EID 11 for the AtomicTest.exe file write:** The file creation would normally produce
an EID 11; EID 29 (file executable detected) fired instead (or as well), which is Sysmon's
PE-detection event. The dataset does include EID 11 events but they pertain to other files (DLLs
loaded, etc.).

**No execution of AtomicTest.exe:** The test only drops the file and creates the firewall rule.
The binary is not executed, so there are no child process events from AtomicTest.exe.

**Windows Firewall audit events:** Not collected due to `policy_change: none` audit policy.

## Assessment

This dataset is notable for combining file-drop and firewall-rule-creation in a single atomic
action, producing correlated Sysmon EID 29 (new PE file in user-writable path) and EID 13
(firewall rule permitting that exact file path) events within milliseconds. The rule value in the
registry includes the full executable path (`App=C:\Users\ACME-WS02$\AtomicTest.exe`), which
directly links the firewall rule to the dropped binary. The SHA256 of AtomicTest.exe is captured,
supporting retrospective threat hunting. Test completed successfully.

## Detection Opportunities Present in This Data

- **Sysmon EID 29:** PE file written to a user-writable path (`C:\Users\`, `C:\ProgramData\`, `%TEMP%`) by powershell.exe or cmd.exe — especially if followed immediately by a firewall rule creation
- **Sysmon EID 13:** `FirewallRules\{GUID}` value containing `App=` pointing to a path outside `%ProgramFiles%` or `%SystemRoot%`
- **Sysmon EID 1:** `netsh.exe` with `advfirewall firewall add rule` and `program=` referencing a user-writable path
- **PowerShell EID 4104:** Script block containing both `Copy-Item` and `netsh advfirewall` in the same block — file staging followed by firewall exception
- **Correlation (high-fidelity):** Sysmon EID 29 (new executable at path X) + Sysmon EID 13 (firewall rule referencing path X) within a short time window on the same host
- **Security EID 4688:** netsh.exe process creation with `program=` path in a non-standard location
