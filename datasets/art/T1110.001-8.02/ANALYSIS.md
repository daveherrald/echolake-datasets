# T1110.001-8: Password Guessing — ESXi - Brute Force Until Account Lockout

## Technique Context

T1110.001 (Password Guessing) covers systematic testing of passwords against specific known accounts. This test targets VMware ESXi hypervisors rather than Windows authentication systems—a significant distinction. It uses `plink.exe` (the command-line SSH client from the PuTTY suite) to attempt SSH connections to an ESXi host, testing a single fixed password against the `root` account repeatedly until the account locks out.

Targeting hypervisor management interfaces is a high-value adversary tactic: ESXi hosts run virtual machines directly, and root access to ESXi provides complete control over all VMs, their storage, and their network interfaces. ESXi brute force via SSH is notably different from AD-targeted attacks because:

1. ESXi does not integrate with Windows authentication; it has its own local account store
2. SSH brute force against ESXi does not generate Windows Security events
3. Network connectivity to ESXi management interfaces (typically port 22 or the vSphere HTTPS port) may exist from workstations in some network configurations

The test executes: `plink.exe -ssh "atomic.local" -l root -pw f0b443ae-9565-11ee-b9d1-0242ac120002` — this is run 5 times in a loop (`$lockout_threshold = 5`), using a UUID-format password that will fail authentication, intentionally triggering lockout.

## What This Dataset Contains

This dataset was collected on ACME-WS06, a Windows 11 Enterprise domain workstation with Microsoft Defender disabled.

**Process Chain (Security EID 4688 / Sysmon EID 1):**

The ART test framework PowerShell (PID 2332) spawns a child PowerShell (PID 6104, tagged `technique_id=T1059.001`) with:

```
"powershell.exe" & {$lockout_threshold = [int]"5"
for ($var = 1; $var -le $lockout_threshold; $var++) {
  C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe -ssh "atomic.local" -l root -pw f0b443ae-9565-11ee-b9d1-0242ac120002
  }}
```

The full command line—including the hardcoded password `f0b443ae-9565-11ee-b9d1-0242ac120002`, target host `atomic.local`, username `root`, and the 5-iteration loop—is captured verbatim in the Sysmon EID 1 and Security EID 4688 events. This is a credential exposure artifact: test credentials are embedded in the command line and appear in security telemetry.

**Image Loads (Sysmon EID 7):**

Twenty-five DLL load events for the test framework PowerShell (PID 2332)—same as T1110.001-4, reflecting identical test framework initialization.

**Process Access (Sysmon EID 10):**

Four events: PID 2332 accesses `whoami.exe` (PID 248) and child PowerShell (PID 6104) with `GrantedAccess: 0x1FFFFF`.

**Named Pipe (Sysmon EID 17):**

Three PSHost pipe creation events for the test framework and cleanup shells.

**File Creation (Sysmon EID 11):**

One EID 11 event: PowerShell startup profile write.

**PowerShell Script Block Logging (EID 4104):**

121 EID 4104 events (no 4103 events). Higher than T1110.001-4 (116), likely reflecting the loop structure and plink invocation overhead in the PowerShell module.

## What This Dataset Does Not Contain

The SSH connections made by plink.exe to `atomic.local` are not present in this dataset. There are no Sysmon EID 3 network connection events for plink.exe's SSH attempts, no EID 22 DNS queries for `atomic.local`, and no indication of whether any of the five connection attempts reached the target or received any response.

Plink.exe itself does not appear as a Sysmon EID 1 process creation in the sample—it is invoked from within the child PowerShell loop, but those EID 1 events are not in the sample set. Plink's binary hash, command line argument structure, and parent-child relationship to the child PowerShell would appear in EID 1.

The target `atomic.local` hostname resolution is not visible. Whether the target was reachable, whether authentication was attempted, and whether any lockout occurred are all outside this dataset's scope—they would be visible only at the target ESXi host's audit logs.

No network telemetry shows the SSH protocol negotiation or authentication failures. The five plink.exe invocations and their outcomes are entirely absent from this workstation-based telemetry.

## Assessment

The primary evidence in this dataset is the child PowerShell command line containing the full plink.exe invocation with hardcoded credentials, target host, and loop structure. Despite the technique targeting an ESXi host rather than Windows authentication, the initial execution footprint on the Windows workstation is captured.

Compared to the defended variant (sysmon 36, security 13, powershell 61), the undefended dataset has very similar Sysmon coverage (37 events) but significantly more PowerShell events (121 vs. 61). The defended run's higher Security event count (13 vs. 4) reflects Defender spawning remediation processes in response to detecting plink.exe.

A notable characteristic of this test: the password `f0b443ae-9565-11ee-b9d1-0242ac120002` appears verbatim in Security and Sysmon telemetry. This is an inherent consequence of command-line credential passing—the `-pw` flag to plink places the password in the process command line, which is then logged by process creation auditing. Any real attacker using this technique with a real credential would similarly expose it in Windows event logs.

The "atomic.local" target hostname is test-specific but indicates the target is a local network resource (not a public internet host). In a real attack, the ESXi management IP or hostname would appear here.

## Detection Opportunities Present in This Data

**Plink.exe with SSH credentials in command line (EID 1 / EID 4688):** `plink.exe -ssh <host> -l <user> -pw <password>` is a credential exposure and brute force indicator. Any occurrence of plink.exe (or putty.exe) with `-l root` targeting non-Windows hosts warrants investigation. The `-pw` flag's appearance in process telemetry is a credential-in-command-line exposure of independent concern.

**Plink.exe spawned by PowerShell in a loop (EID 4104):** The loop structure (`for ($var = 1; $var -le $lockout_threshold; ...)`) in a script block that invokes plink.exe is a direct brute-force indicator. Script block logging captures this pattern if the for loop is within a logged PowerShell execution.

**Plink.exe targeting non-Windows infrastructure from domain workstations:** Any SSH client tool (plink, ssh.exe, OpenSSH) connecting from a domain workstation to hosts outside the Windows environment (`.local` domains resolving to non-DC addresses, IP addresses outside the domain subnet) is a lateral movement or reconnaissance indicator.

**ESXi-side detection (outside this dataset):** The complementary detection lives at the ESXi host or network boundary. Five failed SSH authentication attempts from the same source IP within seconds would generate ESXi authentication logs (viewable via `esxcli system syslog`, `/var/log/auth.log`, or SIEM ingestion of ESXi syslog) and would trigger account lockout if the lockout policy is configured. Network monitoring at the management network segment would show the TCP connection attempts.

**Credentials in process command line (EID 4688 / EID 1):** The appearance of a UUID-format string (`f0b443ae-9565-11ee-b9d1-0242ac120002`) after a `-pw` flag in a plink command line represents a credential in cleartext telemetry. Monitoring for `-pw`, `-password`, or similar flags followed by non-empty values in process command lines is a general credential-exposure detection opportunity.
