# T1546.008-2: Accessibility Features — Replace Binary of Sticky Keys

## Technique Context

T1546.008 (Accessibility Features) also encompasses the direct file replacement variant: instead of registering an IFEO debugger (as in test 1), the attacker overwrites the accessibility binary itself with a shell or backdoor executable. Replacing `sethc.exe` (Sticky Keys — invoked by pressing Shift five times) with `cmd.exe` creates a SYSTEM shell accessible from the Windows logon screen without any credentials. This requires ownership and write permissions on a protected system binary, making it more invasive than the IFEO approach. The file replacement approach has been documented in use since at least 2013 (e.g., by APT groups targeting Windows servers over RDP) and is well-known to endpoint protection vendors. Windows Defender's file integrity protections often block the final copy step, leaving a partial execution chain as telemetry.

## What This Dataset Contains

The dataset spans 5 seconds (2026-03-13 23:40:34–23:40:39) on ACME-WS02 running as NT AUTHORITY\SYSTEM.

**Sysmon (29 events, IDs: 1, 7, 10, 11, 17):** The execution chain is well captured through Sysmon ID=1 (ProcessCreate) events:

1. `whoami.exe` (test framework context check, tagged T1033)
2. `cmd.exe` with the full compound command:
   ```
   "cmd.exe" /c IF NOT EXIST C:\Windows\System32\sethc_backup.exe (copy C:\Windows\System32\sethc.exe C:\Windows\System32\sethc_backup.exe) & takeown /F C:\Windows\System32\sethc.exe /A & icacls C:\Windows\System32\sethc.exe /grant Administrators:F /t & copy /Y C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe
   ```
3. `takeown.exe` with `takeown /F C:\Windows\System32\sethc.exe /A` (tagged T1222.001)
4. `icacls.exe` with `icacls C:\Windows\System32\sethc.exe /grant Administrators:F /t` (tagged T1222.001)

Sysmon ID=11 (FileCreate) confirms that `C:\Windows\System32\sethc.exe` was written — the copy succeeded. The timestamp on the FileCreate shows `CreationUtcTime: 2026-03-13 02:04:52.143`, indicating this reflects the copy of `cmd.exe` (whose original creation time is preserved).

**Application (3 events, ID: 15):** Three Application log events record `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON`, indicating Defender reacted to the file modification but restored its active state after detecting the change to a system binary.

**Security (15 events, IDs: 4688, 4689, 4703):** Process creation and termination events for `cmd.exe`, `takeown.exe`, and `icacls.exe`, providing independent command-line confirmation.

**PowerShell (34 events, IDs: 4103, 4104):** Test framework boilerplate only.

## What This Dataset Does Not Contain

- **No Defender block:** Unlike many tests where Defender blocks with exit code 0xC0000022 (STATUS_ACCESS_DENIED), the file copy in this test succeeded — Sysmon ID=11 confirms `sethc.exe` was written. The Application log ID=15 events suggest Defender detected the modification but did not prevent it.
- **No Sysmon ID=13 (RegistryValueSet):** This test uses file replacement, not IFEO registry modification, so there are no registry indicator events.
- **No trigger execution:** No accessibility binary launch from winlogon (the post-persistence trigger) is present in this window.
- **No Sysmon ID=7 (ImageLoad) for the replaced binary:** Since the replaced `sethc.exe` (now `cmd.exe`) was not executed, there are no DLL load events for it.

## Assessment

This dataset captures a complete file replacement attack chain including the ownership-taking and permission-modification steps. The Sysmon ID=11 confirming the write to `C:\Windows\System32\sethc.exe` is a highly specific indicator. The Application log ID=15 events showing Defender's status restoration are interesting context — they indicate Defender noticed but did not block the replacement, which is relevant for defenders assessing their coverage. The `takeown.exe` and `icacls.exe` command lines are themselves strong pre-indicators. The dataset would be strengthened by adding Security ID=4670 (permissions on object were changed) events, which would require object access auditing to be enabled.

## Detection Opportunities Present in This Data

1. **Sysmon ID=11:** A file write to any accessibility binary path in `C:\Windows\System32\` (sethc.exe, osk.exe, utilman.exe, magnify.exe, narrator.exe, atbroker.exe) that changes its hash is a critical indicator — these binaries have no legitimate reason to be modified in production.
2. **Sysmon ID=1 / Security ID=4688:** `takeown.exe /F C:\Windows\System32\sethc.exe` (or any protected accessibility binary) is a strong pre-indicator of file replacement intent.
3. **Sysmon ID=1 / Security ID=4688:** `icacls.exe <accessibility_binary> /grant Administrators:F` in the same time window as a `takeown.exe` call on the same file creates a reliable two-event detection chain.
4. **Security ID=4688:** The compound `cmd.exe /c` command line containing both `takeown` and `icacls` and `copy /Y cmd.exe <accessibility_binary>` is an extremely specific indicator pattern.
5. **Application log ID=15:** Windows Defender status state change events coinciding with a file write to System32 can serve as a corroborating signal, particularly when Defender does not block the write.
