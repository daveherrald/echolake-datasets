# T1505.002-1: Server Software Component — Transport Agent (MS Exchange Persistence)

## Technique Context

T1505.002 (Transport Agent) describes the abuse of Microsoft Exchange Server transport agents as a persistence mechanism. Exchange transport agents are COM-based plugins that hook into the mail transport pipeline to inspect, modify, or act on email messages as they flow through the Exchange server. Legitimate agents are used for anti-spam, DLP, and encryption. Adversaries — notably APT groups like Turla and the threat actor behind Operation Exchange Marauder — have installed malicious transport agents that exfiltrate email content, intercept credentials in email, or provide a command-and-control channel delivered through incoming email. This technique is particularly insidious because the agent runs inside the Exchange transport service with SYSTEM-level privileges, survives reboots, and email traffic provides a natural cover channel.

Detection teams focus on `Install-TransportAgent` and `Enable-TransportAgent` PowerShell cmdlet executions, unexpected DLL registrations in the Exchange pipeline, and Exchange management shell invocations by non-administrative accounts.

## What This Dataset Contains

The technique is simulated via PowerShell Exchange Management Shell cmdlets captured in Security Event ID 4688, Sysmon Event ID 1, and PowerShell Event ID 4104:

```
powershell.exe & {
  Install-TransportAgent -Name "Security Interop Agent"
    -TransportAgentFactory Microsoft.Exchange.Security.Interop.SecurityInteropAgentFactory
    -AssemblyPath "c:\program files\microsoft\Exchange Server\v15\bin\Microsoft.Exchange.Security.Interop.dll"
  Enable-TransportAgent "Security Interop Agent"
  Get-TransportAgent | Format-List Name,Enabled
}
```

The full command — including the transport agent name, factory class, and DLL assembly path — is captured across all three channels. The PowerShell 4104 script block logging records both the wrapped invocation and the raw script body. The DLL path (`c:\program files\microsoft\Exchange Server\v15\bin\Microsoft.Exchange.Security.Interop.dll`) names a legitimate Exchange component, simulating an attacker registering a known-good DLL as a transport agent to demonstrate the registration pattern without deploying a malicious payload.

The dataset also captures the expected supporting events: Sysmon image load events (Event ID 7) for DLLs loaded by `powershell.exe`, pipe creation events (Event ID 17), and process access events (Event ID 10). Security Events ID 4688/4689 confirm PowerShell process lifecycle under NT AUTHORITY\SYSTEM.

## What This Dataset Does Not Contain

- **No Exchange Management Shell loading**: On a workstation without Exchange Server installed, `Install-TransportAgent` and `Enable-TransportAgent` are not available cmdlets. The PowerShell execution generates error conditions (the Exchange snap-in is not present). The technique simulation captures the attempt and cmdlet invocation pattern, but the actual agent registration does not complete on this host.
- **No Exchange-specific event logs**: Exchange Server operational logs (MSExchange Transport, MSExchange Diagnostics) that would record a transport agent being registered are absent — those logs only exist on Exchange Server hosts.
- **No DLL file creation or modification**: The `Microsoft.Exchange.Security.Interop.dll` assembly path referenced in the cmdlet is not created or modified during this test; the test relies on the path reference being captured in telemetry.
- **No registry entries for the transport agent**: A successful `Install-TransportAgent` would write to the Exchange configuration in Active Directory or a local configuration file. Those changes are not captured in this Windows event telemetry.

## Assessment

This dataset provides good evidence of the attempted invocation pattern for Exchange transport agent installation. The full PowerShell command including the agent name, factory class, and DLL assembly path is captured across multiple channels. For detection engineering purposes, the most valuable artifact is the script block or command-line evidence of `Install-TransportAgent` being invoked from a non-Exchange-server context by SYSTEM — a pattern that should be rare on managed endpoints. The dataset's primary limitation is that it simulates the technique on a workstation where Exchange is not installed; a deployment on an actual Exchange server would produce richer Exchange-specific telemetry. The dataset is most useful for building detection rules around the PowerShell cmdlet signatures rather than for correlating with Exchange transport logs.

## Detection Opportunities Present in This Data

1. **PowerShell command line (Security 4688/Sysmon Event ID 1) or script block (4104) containing `Install-TransportAgent`** — This cmdlet has no legitimate use outside Exchange server administration; its invocation from an endpoint workstation by SYSTEM is immediately suspicious.
2. **`Enable-TransportAgent` followed by `Get-TransportAgent` in the same PowerShell session** — The three-cmdlet sequence (install, enable, verify) is characteristic of a complete agent registration workflow and is captured as a unit in the script block.
3. **PowerShell referencing Exchange Server DLL paths (`c:\program files\microsoft\Exchange Server\v15\bin\`)** — DLL assembly paths pointing to Exchange binaries in PowerShell command lines on non-Exchange hosts indicate attempts to load Exchange management modules or register Exchange components.
4. **`-TransportAgentFactory` parameter with a `SecurityInteropAgentFactory` or similar factory class name in PowerShell**— The factory class name is a specific technical indicator; real attacks have used custom factory class names that follow a naming convention distinguishable from legitimate Exchange agents.
5. **SYSTEM-context PowerShell invoking Exchange Management Shell cmdlets** — Legitimate Exchange administration is typically performed by Exchange administrators in their own user context, not by SYSTEM-context processes; this execution context is a key differentiator.
