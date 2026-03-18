# T1136.002-2: Domain Account — Create a new account similar to ANONYMOUS LOGON

## Technique Context

T1136.002 (Domain Account) involves adversaries creating new domain user accounts to establish persistence and maintain access to compromised environments. Creating accounts that mimic system accounts like "ANONYMOUS LOGON" is a common evasion technique, as these names may blend in with legitimate system accounts and avoid scrutiny. This technique provides attackers with persistent access that survives system reboots and can be used across domain-joined systems. Detection engineers typically focus on monitoring account creation events, unusual account names (especially those mimicking system accounts), and the use of administrative tools like `net user` with domain flags.

## What This Dataset Contains

This dataset captures a failed attempt to create a domain account using the `net user` command. The key evidence includes:

**Process chain execution from Security events:**
- PowerShell (PID 13532) spawns cmd.exe with command line `"cmd.exe" /c net user "ANONYMOUS  LOGON" "T1136_pass123!" /add /domain`
- cmd.exe spawns net.exe with the same account creation parameters
- net.exe spawns net1.exe (the actual implementation) with command `C:\Windows\system32\net1  user "ANONYMOUS  LOGON" "T1136_pass123!" /add /domain`

**Failure indicators:**
- All processes in the chain exit with error codes: net1.exe and net.exe exit with status 0x2 (indicating command failure)
- No account creation events (4720) appear in the Security log

**Sysmon process tracking:**
- Sysmon EID 1 events capture the same process creations with full command lines
- ProcessCreate events tagged with relevant MITRE techniques (T1087.001 for net.exe, T1018 for domain operations)

**PowerShell telemetry:**
- Only test framework boilerplate captured (Set-StrictMode, Set-ExecutionPolicy Bypass scriptblocks)
- No evidence of the actual account creation script content

## What This Dataset Does Not Contain

The dataset lacks successful account creation telemetry because the command failed (likely due to insufficient domain privileges or domain controller connectivity issues). Missing elements include:

- Security event 4720 (A user account was created) which would appear on successful domain account creation
- Domain controller logs showing the account creation request
- Active Directory object creation events
- Any evidence of successful authentication using the attempted account
- The specific error message from the net command failure

The failure appears to be operational rather than due to Windows Defender blocking, as the process chain completes normally with error exit codes rather than access denied (0xC0000022) status.

## Assessment

This dataset provides excellent visibility into failed domain account creation attempts. The Security audit policy with command-line logging captures the complete attack chain with full command arguments, including the suspicious account name and password. Sysmon ProcessCreate events complement this with additional process metadata and MITRE technique tagging. While the technique execution failed, the telemetry demonstrates how real-world attacks might be detected even when they don't succeed. The presence of both successful process execution and clear failure indicators makes this valuable for understanding both detection opportunities and common attack failure modes.

## Detection Opportunities Present in This Data

1. **Suspicious domain account creation attempts** - Monitor Security EID 4688 for `net user` commands with `/add /domain` flags, especially with non-standard account names
2. **System account name mimicry** - Alert on account creation attempts using names like "ANONYMOUS LOGON" or other system account patterns
3. **PowerShell spawning account management tools** - Detect PowerShell processes creating cmd.exe or net.exe for user management operations
4. **Net.exe domain operations** - Monitor for net.exe execution with domain-related parameters (`/domain`) from non-administrative contexts
5. **Failed account creation correlation** - Combine process execution events with missing account creation events to identify failed but suspicious attempts
6. **Process chain analysis** - Track the full execution chain from PowerShell → cmd.exe → net.exe → net1.exe for account management activities
7. **Command-line password exposure** - Alert on plaintext passwords in command lines for account creation operations
