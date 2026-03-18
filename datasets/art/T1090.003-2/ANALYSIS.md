# T1090.003-2: Multi-hop Proxy — Tor Proxy Usage - Windows

## Technique Context

T1090.003 Multi-hop Proxy represents attackers using intermediate systems to relay network traffic and obscure their true location. Tor is one of the most common multi-hop proxy implementations, routing traffic through multiple encrypted relays to provide anonymity. Attackers use Tor for command and control communications, data exfiltration, and accessing compromised systems while hiding their origin. The detection community focuses on identifying Tor client installations, unusual proxy configurations, and the characteristic network patterns of onion routing protocols. This technique is particularly challenging to detect when attackers use legitimate Tor installations or when network monitoring capabilities are limited.

## What This Dataset Contains

This dataset captures a PowerShell-driven attempt to execute the Tor client binary. The process chain shows: PowerShell (PID 19992) → PowerShell (PID 20216) → cmd.exe (PID 22384) → PowerShell (PID 24224) → cmd.exe (PID 23396), ultimately attempting to execute "C:\AtomicRedTeam\atomics\..\ExternalPayloads\tor\Tor\tor.exe". 

The Security event log reveals the command execution attempt in Security 4688: `"C:\Windows\system32\cmd.exe" /c C:\AtomicRedTeam\atomics\..\ExternalPayloads\tor\Tor\tor.exe`. However, the cmd.exe process exits with status 0x1 (failure), indicating the Tor executable either doesn't exist at that path or fails to launch.

PowerShell script block logging captures the technique's core commands: `invoke-expression 'cmd /c start powershell -Command {cmd /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\tor\Tor\tor.exe"}'` and includes a 60-second sleep timer followed by `stop-process -name "tor"` cleanup logic.

Sysmon ProcessCreate events (EID 1) show the full process chain with exact command lines, including base64-encoded PowerShell parameters. The encoded command decodes to the Tor executable path. No Tor process creation is captured, confirming the execution failed.

## What This Dataset Does Not Contain

The dataset lacks the actual Tor executable at the expected path, so no tor.exe process creation occurs. Consequently, there are no network connection events (Sysmon EID 3) showing Tor's characteristic connections to directory servers or relay nodes. No DNS queries (Sysmon EID 22) for .onion domains or Tor infrastructure are present. The dataset contains no file creation events for Tor configuration files, data directories, or cached consensus documents that would normally accompany a successful Tor installation. Additionally, there are no registry modifications related to proxy settings or Tor configuration that might occur with some Tor implementations.

## Assessment

This dataset provides good detection value for the initial phases of Tor proxy usage attempts, particularly the PowerShell execution patterns and command-line artifacts. The Security 4688 events with full command-line logging capture the technique's core indicators, while Sysmon ProcessCreate events provide additional process genealogy context. However, the dataset's utility is limited by the failed execution - it demonstrates attempt telemetry but not successful Tor proxy establishment. For comprehensive T1090.003 detection development, you would need additional datasets showing successful Tor execution with accompanying network telemetry and configuration artifacts.

## Detection Opportunities Present in This Data

1. **Tor executable path detection** - Monitor for command lines containing paths to "tor.exe" or similar Tor binary names in Security 4688 or Sysmon EID 1 events
2. **PowerShell Tor invocation patterns** - Detect PowerShell script blocks (EID 4104) containing "tor.exe" execution attempts combined with process management (start-process, stop-process)
3. **Base64 encoded Tor commands** - Hunt for base64-encoded PowerShell commands that decode to Tor executable paths using the `-encodedCommand` parameter
4. **Nested PowerShell/cmd.exe proxy execution** - Identify process chains where PowerShell spawns cmd.exe which spawns another PowerShell instance, particularly with suspicious command patterns
5. **Process exit code anomalies** - Monitor for cmd.exe processes with exit status 0x1 when attempting to execute files in non-standard directories like "\ExternalPayloads\"
6. **AtomicRedTeam artifacts** - Flag command lines referencing "AtomicRedTeam" or "ExternalPayloads" directory structures as potential testing or attack activity
