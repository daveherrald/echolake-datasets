# T1562.004-21: LockBit Black — Unusual Windows Firewall Registry Modification (PowerShell)

## Technique Context

T1562.004 covers firewall disablement. Test 21 is the PowerShell variant of test 20 — it
implements the same LockBit Black Group Policy firewall disablement pattern but uses
`New-ItemProperty` instead of reg.exe. The script block:

```powershell
New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
  -Name EnableFirewall -PropertyType DWORD -Value 0 -Force
New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"
  -Name EnableFirewall -PropertyType DWORD -Value 0 -Force
```

This PowerShell-native approach avoids spawning child processes, leaving a different telemetry
footprint than the cmd/reg.exe variant. The technique targets the same Group Policy path as test
20, with identical downstream effect on Windows Firewall policy enforcement.

## What This Dataset Contains

**Sysmon (36 events):** Sysmon ID 1 captures:

- `whoami.exe` (RuleName: T1033)
- `powershell.exe & {New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name EnableFirewall -PropertyType DWORD -Value 0 -Force ...}` (RuleName: T1059.001)

Unlike test 20, no cmd.exe or reg.exe child processes appear — the write is performed entirely
within the PowerShell process. Sysmon 7 (image loads including MpOAV.dll, MpClient.dll), 10
(process access), 11 (file create for PS profile), and 17 (named pipe) events are present.

**Security (10 events):** The smallest security event count of the T1562.004 group. Only
4688/4689 for whoami and PowerShell, plus 4703 (token adjustment). No cmd.exe or reg.exe in the
process chain.

**PowerShell (39 events):** Script block (4104) captures the full technique payload:

```
& {New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
-Name EnableFirewall -PropertyType DWORD -Value 0 -Force
New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"
-Name EnableFirewall -PropertyType DWORD -Value 0 -Force}
```

Module logging (4103) records both `New-ItemProperty` invocations separately with all parameter
bindings, including the path, property name (`EnableFirewall`), type (`DWORD`), and value (`0`).
ART test framework boilerplate fills the remaining events.

## What This Dataset Does Not Contain (and Why)

**No cmd.exe or reg.exe.** This is the defining contrast with test 20 — the entire action is
in-process PowerShell. Detections relying on reg.exe command-line inspection will not fire.

**No Sysmon 13.** As with test 20, the Group Policy firewall path is not monitored by the
sysmon-modular registry rules. The write is confirmed only via PowerShell 4103 module logging
and Sysmon 1 command-line capture.

**No Windows Firewall Operational events** or service-change notifications for the same reasons
as test 20.

**Sysmon ProcessCreate include filtering** restricts coverage. PowerShell is captured under the
T1059.001 rule; no secondary processes exist to miss.

## Assessment

The test completed successfully. The PowerShell 4103 module log provides definitive confirmation
that both `New-ItemProperty` calls executed. The Sysmon 1 command line contains the full payload.
This dataset cleanly illustrates why defenders should not rely solely on reg.exe monitoring for
Group Policy firewall path writes — the same effect is achievable entirely within PowerShell.

## Detection Opportunities Present in This Data

- **PowerShell 4103:** `New-ItemProperty` with path `HKLM:\SOFTWARE\Policies\Microsoft\
  WindowsFirewall\*Profile`, name `EnableFirewall`, value `0` — this is a precise behavioral
  indicator that survives PowerShell obfuscation of the cmdlet name.
- **PowerShell 4104:** The script block containing `EnableFirewall` and `DWORD` targeting the
  `WindowsFirewall\DomainProfile` or `StandardProfile` path is signable.
- **Sysmon 1 / Security 4688:** PowerShell command line containing `New-ItemProperty`,
  `WindowsFirewall`, `EnableFirewall`, and `-Value 0` together.
- **Coverage comparison with test 20:** reg.exe-based detection (test 20) and PowerShell-based
  detection (test 21) are complementary; neither alone covers both variants.
- **LockBit correlation:** The dual-profile DomainProfile+StandardProfile targeting pattern in
  a single invocation is a strong LockBit Black behavioral signature.
