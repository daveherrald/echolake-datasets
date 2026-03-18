# T1654-1: Log Enumeration — Get-EventLog To Enumerate Windows Security Log

## Technique Context

T1654 (Log Enumeration) covers adversary attempts to read Windows event logs, typically to understand what monitoring is in place, locate evidence of their own actions, or gather information about user activity and system events. The PowerShell `Get-EventLog` cmdlet provides a simple way to read event log contents programmatically. Adversaries use log enumeration both for situational awareness and as a precursor to log tampering (T1070.001).

## What This Dataset Contains

This dataset contains no bundled event files. The `files.bundled` list in `dataset.yaml` is empty, and the `provenance.verification.source_counts` and `dest_counts` are both empty objects (`{}`).

The test ran as NT AUTHORITY\SYSTEM on ACME-WS02 (Windows 11 Enterprise, acme.local domain member) between approximately 14:46:33 and 14:46:42 UTC on 2026-03-14, per the `timestamp_range` in the dataset metadata.

## What This Dataset Does Not Contain (and Why)

No telemetry was collected for this test. This outcome has a plausible explanation: `Get-EventLog` is a PowerShell cmdlet that reads log data but does not spawn external processes. The test execution context is NT AUTHORITY\SYSTEM, and reading the Security log from that context is a routine OS activity. The following factors combine to produce an empty dataset:

- **No external process spawned**: `Get-EventLog` operates entirely within the PowerShell process. The sysmon-modular ProcessCreate include rules have no matching entry for this behavior, so no Sysmon EID 1 fires.
- **Security EID 4688 requires external process**: Because no child process is spawned, no Security process creation event is generated.
- **Object access auditing disabled**: The audit policy has `object_access: none`. Reading the Security log would normally generate Object Access events if auditing were enabled on the log file; without it, no Security events appear.
- **PowerShell events may have been filtered out**: It is possible that PowerShell script block logging captured the `Get-EventLog` invocation, but the event collection window or filtering did not include events from this test's time window. Alternatively, the test may have failed silently (e.g., `Get-EventLog -LogName Security` may require specific privileges or the cmdlet may not be available on Windows 11 22H2 in the same way as older Windows versions — `Get-WinEvent` is the preferred replacement).

## Assessment

This is a null-result dataset. It documents that the ART test for T1654-1 (using `Get-EventLog`) produced no captured telemetry under this collection configuration. This is itself informative: `Get-EventLog` used in isolation on a modern Windows 11 system, without external process spawning, is effectively invisible to process-based detection sources (Sysmon ProcessCreate, Security 4688) and to object access auditing when disabled.

Defenders should not rely on process-based detection for `Get-EventLog` usage. PowerShell script block logging (EID 4104) would be the only reliable detection source, contingent on the PowerShell process being captured in the logging window.

## Detection Opportunities Present in This Data

No events are present in this dataset. Potential detection approaches for this technique in a production environment would require:

- **PowerShell EID 4104**: Script block logging would capture `Get-EventLog -LogName Security` if PowerShell logging is enabled and the log collection window is not missed.
- **Object access auditing on the Security log**: Enabling audit policy for object access on `C:\Windows\System32\winevt\Logs\Security.evtx` would generate EID 4663 events when the log is read by non-standard processes.
- **PowerShell EID 4103 module logging**: `Get-EventLog` would appear in module-level logging if the Security log is successfully read.
