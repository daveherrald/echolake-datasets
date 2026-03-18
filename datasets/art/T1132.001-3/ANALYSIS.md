# T1132.001-3: Standard Encoding — XOR Encoded data.

## Technique Context

T1132.001 (Standard Encoding) involves adversaries using standard data encoding techniques to make their command and control communications look legitimate or evade detection. XOR encoding is one of the most common approaches, as it's simple to implement, reversible, and can make malicious payloads appear as random data. Attackers frequently use XOR to encode exfiltrated data, command payloads, or network communications to bypass content inspection and signature-based detection. The detection community focuses on identifying suspicious encoding/decoding operations in scripts, unusual character patterns in network traffic, and the presence of encoding functions combined with network communications.

## What This Dataset Contains

This dataset captures a PowerShell-based XOR encoding demonstration that encrypts data and attempts to exfiltrate it via HTTP POST. The technique evidence is primarily contained in:

**PowerShell Script Block Logging (EID 4104)**: The complete XOR encoding script is captured: `$plaintext = ([system.Text.Encoding]::UTF8.getBytes("Path\n----\nC:\Users\victim")) $key = "abcdefghijklmnopqrstuvwxyz123456" $cyphertext = @(); for ($i = 0; $i -lt $plaintext.Count; $i++) { $cyphertext += $plaintext[$i] -bxor $key[$i % $key.Length]; } $cyphertext = [system.Text.Encoding]::UTF8.getString($cyphertext)`

**Command Invocation Logging (EID 4103)**: Shows the Invoke-WebRequest execution with the XOR-encoded payload: `ParameterBinding(Invoke-WebRequest): name="Body"; value="1___9_JEDG7_.T3%____"`

**Security Process Creation (EID 4688)**: Captures the full command line including the embedded XOR encoding script in the PowerShell process creation event.

**Sysmon Process Creation (EID 1)**: Shows the PowerShell process that executes the XOR encoding operation.

**Network Activity Attempt**: PowerShell error logging (EID 4100) shows the HTTP request failed with "The remote server returned an error: (405) Method Not Allowed" when attempting to POST to example.com.

The dataset shows both the encoding process (converting "Path\n----\nC:\Users\victim" to "1___9_JEDG7_.T3%____" using the key "abcdefghijklmnopqrstuvwxyz123456") and the attempted network transmission.

## What This Dataset Does Not Contain

The dataset lacks successful network telemetry because the HTTP POST to example.com failed with a 405 error. There are no Sysmon network connection events (EID 3) or DNS queries (EID 22) because the connection attempt was unsuccessful. Windows Firewall or network-level logs that might show the outbound connection attempt are not present. The technique execution was complete from a host perspective, but the network component failed, limiting the available network-based detection opportunities.

## Assessment

This dataset provides excellent coverage of XOR encoding detection opportunities from a host-based perspective. The combination of PowerShell script block logging, command invocation logging, and process creation events creates multiple detection vectors. The script block logs capture the exact encoding algorithm, key, and plaintext, while the command invocation logs show the encoded result. The failed network transmission actually enhances the dataset's utility by demonstrating how encoding techniques can be detected even when exfiltration fails. This is particularly valuable for detection engineering since many real-world scenarios involve partial technique execution.

## Detection Opportunities Present in This Data

1. **XOR encoding operations in PowerShell script blocks** - Detect `-bxor` operations combined with loops and array operations in EID 4104 events
2. **Suspicious encoding patterns** - Identify PowerShell scripts containing UTF8.getBytes, getString, and bitwise operations together
3. **Command line XOR patterns** - Hunt for `-bxor` operations in Security EID 4688 command line fields
4. **Encoding key patterns** - Detect long alphanumeric strings used as XOR keys (like "abcdefghijklmnopqrstuvwxyz123456")
5. **PowerShell encoding combined with web requests** - Correlate Invoke-WebRequest usage with prior encoding operations in the same script
6. **Suspicious HTTP POST bodies** - Identify unusual character patterns in HTTP request bodies that may indicate encoded data
7. **Process chain analysis** - Detect PowerShell processes spawning other PowerShell processes for encoding operations
8. **Failed network requests with encoded payloads** - Use PowerShell error events to identify attempted exfiltration with suspicious body content
