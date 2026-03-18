# T1490-4: Inhibit System Recovery — Disable Windows Recovery Console Repair

## Technique Context

MITRE ATT&CK T1490 (Inhibit System Recovery) includes modification of Boot Configuration Data (BCD) to prevent the Windows Recovery Environment from repairing the system after a ransomware attack. The two `bcdedit.exe` commands in this test — `/set {default} bootstatuspolicy ignoreallfailures` and `/set {default} recoveryenabled no` — are among the most frequently observed ransomware pre-encryption steps. `bootstatuspolicy ignoreallfailures` suppresses the automatic repair boot screen that appears after a failed boot, ensuring the system reboots directly into the encrypted operating system without prompting for recovery. `recoveryenabled no` disables the Windows Recovery Environment entirely. These two commands appear together in Ryuk, Conti, LockBit, and many other ransomware families. They have virtually no legitimate administrative use case and are treated as a high-confidence ransomware indicator by most endpoint and SIEM vendors.

## What This Dataset Contains

**Sysmon (Event ID 1) — ProcessCreate:**
The attack chain is captured completely. The test framework launches `cmd.exe /c bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures & bcdedit.exe /set {default} recoveryenabled no`. Both `bcdedit.exe` invocations are spawned and captured individually with their full command lines, running as `NT AUTHORITY\SYSTEM` from `C:\Windows\Temp\`. Sysmon tags all relevant events with `technique_id=T1490,technique_name=Inhibit System Recovery`. The `cmd.exe` wrapper is tagged with `technique_id=T1059.003,technique_name=Windows Command Shell`.

The full chain in Sysmon:
- `whoami.exe` (test framework preflight, tagged T1033)
- `cmd.exe /c bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures & bcdedit.exe /set {default} recoveryenabled no`
- `bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures`
- `bcdedit.exe /set {default} recoveryenabled no`

**Security (Event IDs 4688/4689/4703):**
Confirms the same process chain. Both `bcdedit.exe` processes exit with status `0x0` — both BCD modifications succeeded. Token right adjustment events (4703) for the `bcdedit.exe` processes are present, reflecting privilege use during BCD modification. No Defender block or access denial occurred.

**PowerShell channel:** Contains only `Set-StrictMode` and `Set-ExecutionPolicy -Bypass` test framework boilerplate. No technique-relevant content.

## What This Dataset Does Not Contain

- **No BCD store modification events.** There is no dedicated Windows event for BCD key changes. The only way to detect the actual configuration change is through process/command-line telemetry or periodic BCD state comparison. This dataset confirms the commands ran successfully but does not include a direct "BCD changed" event.
- **No Sysmon EID 13 (RegistryEvent)** capturing BCD registry writes. BCD is stored in `\BCD00000000` on the EFI System Partition or as `C:\Boot\BCD`, and writes to it do not generate standard HKLM registry events.
- **No Windows Event Log entries** from the BCD/bootmgr subsystem confirming the policy change was applied.
- **No Sysmon EID 11 (FileCreate)** for the BCD file modification. The BCD binary file update is not captured.

## Assessment

For detection engineering this is a high-quality dataset for the bcdedit recovery-disable use case. Both commands are captured with their exact argument strings in two independent sources, both exit successfully, and the process chain is unambiguous. The absence of BCD-specific confirmation events is a real-world limitation of Windows logging, not a gap in this collection — the process and command-line telemetry is what defenders actually rely on for this detection. The dataset would benefit from inclusion of Sysmon EID 13 to show what registry-adjacent artifacts bcdedit touches, but that is an enhancement rather than a deficiency.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1 — `bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures`** — exact command string match; Sysmon tags this T1490 directly.
2. **Sysmon EID 1 — `bcdedit.exe /set {default} recoveryenabled no`** — high-confidence companion indicator; the combination of both commands in the same session is a near-certain ransomware pre-encryption pattern.
3. **Security EID 4688 — `bcdedit.exe` with `/set {default} recoveryenabled no` or `bootstatuspolicy ignoreallfailures`** arguments — command-line auditing provides this independently of Sysmon.
4. **`cmd.exe /c bcdedit.exe ... & bcdedit.exe ...`** single command line chaining both operations — the ampersand-chained double invocation is a specific pattern observed in multiple ransomware families.
5. **Security EID 4689 exit status `0x0`** for both `bcdedit.exe` processes — confirms successful BCD modification; useful as a post-execution confirmation when combined with the creation events.
6. **Process chain from SYSTEM/TEMP** — `bcdedit.exe` launched by `cmd.exe` from `C:\Windows\TEMP\` under `NT AUTHORITY\SYSTEM` has no legitimate administrative precedent.
