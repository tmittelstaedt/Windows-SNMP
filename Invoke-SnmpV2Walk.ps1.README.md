\# Invoke-SnmpV2Walk.ps1



A pure PowerShell implementation of an \*\*SNMPv2c WALK\*\* client built on native .NET UDP sockets (`System.Net.Sockets.UdpClient`) and custom ASN.1 BER encoding/decoding. 



It traverses an entire MIB subtree via sequential `GetNextRequest` (`0xA1`) PDUs without requiring external binaries, compiled DLLs, or third-party modules—avoiding Windows Smart App Control and WDAC code-signing blocks.



\---



\## 1. Prerequisites \& Loading Into Your Session



Before calling `Invoke-SnmpV2Walk`, you must handle two PowerShell session requirements: \*\*Execution Policy\*\* and \*\*Dot-Sourcing\*\*.



\### Step A: Allow Script Execution in the Current Session

Windows clients default to the `Restricted` execution policy, which blocks `.ps1` files from loading. Run the following command to bypass the policy for your \*\*current PowerShell window only\*\* (this automatically resets when you close the terminal):



```powershell

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

```



\### Step B: Dot-Source the Script File

Because `Invoke-SnmpV2Walk.ps1` defines reusable functions (`Invoke-SnmpV2Walk` and `Parse-SnmpWalkResponse`) rather than executing inline, you must \*\*dot-source\*\* the script using a leading period and space (`. `) so the functions stay loaded in your active session scope:



```powershell

. C:\\scripts\\Invoke-SnmpV2Walk.ps1

```



> \*\*Warning:\*\* Running `.\\Invoke-SnmpV2Walk.ps1` without the leading `. ` executes the file in a temporary child scope and immediately discards the functions when the script exits, resulting in a \*"term is not recognized"\* error.



\### Required .NET Assemblies

All required classes (`System.Net.Sockets.UdpClient`, `System.Net.IPEndPoint`, `System.Text.Encoding`, and `System.Collections.Generic.List<T>`) are built into standard Windows PowerShell 5.1 and PowerShell 7+. No `Add-Type` calls or external module imports are needed.



\---



\## 2. Parameters



| Parameter | Type | Required | Default | Description |

| :--- | :--- | :---: | :--- | :--- |

| `-TargetIP` | `\[string]` | Yes | — | IPv4 address of the target SNMP agent (e.g., `"172.16.1.2"`). |

| `-RootOID` | `\[string]` | Yes | — | Base OID subtree to walk (leading dot optional, e.g., `"1.3.6.1.2.1.1"`). |

| `-Community` | `\[string]` | No | `"public"` | SNMPv2c read-only community string. |

| `-Port` | `\[int]` | No | `161` | Target UDP port for SNMP queries. |

| `-TimeoutMs` | `\[int]` | No | `3000` | UDP socket receive timeout in milliseconds per hop. |

| `-MaxResults` | `\[int]` | No | `10000` | Safety cap on maximum OIDs retrieved in a single walk. |



\---



\## 3. Usage Examples



\### Walk the System MIB Subtree

Load the script into your session and walk the entire MIB-2 `system` branch (`1.3.6.1.2.1.1`):



```powershell

\# 1. Prepare session and dot-source the script

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

. C:\\scripts\\Invoke-SnmpV2Walk.ps1



\# 2. Walk the system subtree

Invoke-SnmpV2Walk -TargetIP "172.16.1.2" -Community "public" -RootOID "1.3.6.1.2.1.1"

```



\#### Sample Output

```text

OID                   Type Value

\---                   ---- -----

1.3.6.1.2.1.1.1.0     0x04 GS724TS

1.3.6.1.2.1.1.2.0     0x06 1.3.6.1.4.1.4526.100.10.4

1.3.6.1.2.1.1.3.0     0x43 6.00:27:30

1.3.6.1.2.1.1.4.0     0x04 Ted Mittelstaedt

1.3.6.1.2.1.1.5.0     0x04 switch.example.com

1.3.6.1.2.1.1.6.0     0x04 Teds Microcolocate

1.3.6.1.2.1.1.7.0     0x02 2

1.3.6.1.2.1.1.8.0     0x43 00:00:00

1.3.6.1.2.1.1.9.1.2.1 0x06 1.3.6.1.4.1.89.73

1.3.6.1.2.1.1.9.1.3.1 0x04 RS capabilities

1.3.6.1.2.1.1.9.1.4.1 0x43 00:00:00

```



\### Walk Switch Interface Names \& MAC Addresses

Because `Invoke-SnmpV2Walk` streams `\[PSCustomObject]` records directly to the PowerShell pipeline as each packet arrives, you can filter or export results with standard cmdlets:



```powershell

\# List all switch port descriptions (ifDescr)

Invoke-SnmpV2Walk -TargetIP "172.16.1.2" -Community "public" -RootOID "1.3.6.1.2.1.2.2.1.2"



\# List all port MAC addresses (ifPhysAddress) and export to CSV

Invoke-SnmpV2Walk -TargetIP "172.16.1.2" -Community "public" -RootOID "1.3.6.1.2.1.2.2.1.6" |

&#x20;   Export-Csv -Path "C:\\scripts\\switch-macs.csv" -NoTypeInformation

```



\---



\## 4. Supported ASN.1 / SNMP Data Types



The built-in `Parse-SnmpWalkResponse` decoder automatically translates the following BER tags:



| BER Tag | SNMP Type | PowerShell Output Format |

| :--- | :--- | :--- |

| `0x02` | `INTEGER` | `\[int64]` |

| `0x04` | `OCTET STRING` | ASCII `\[string]` for printable text; colon-separated hex (`00:1A:2B:...`) for binary/MAC values |

| `0x05` | `NULL` | `"NULL"` |

| `0x06` | `OBJECT IDENTIFIER` | Dotted-decimal OID `\[string]` (e.g., `1.3.6.1.4.1.4526.100.10.4`) |

| `0x40` | `IpAddress` | Dotted-quad `\[string]` (e.g., `172.16.1.2`) |

| `0x41` | `Counter32` | `\[uint64]` |

| `0x42` | `Gauge32` | `\[uint64]` |

| `0x43` | `TimeTicks` | Formatted `\[TimeSpan]` string (`d.hh:mm:ss`) |

| `0x46` | `Counter64` | `\[uint64]` |

| `0x80` / `0x81` / `0x82` | Exception Tags | `NoSuchObject`, `NoSuchInstance`, or `EndOfMibView` (terminates walk) |

| \*Other\* | Unhandled Tag | `Raw Hex (Tag 0xXX): AA-BB-...` |



\---



\## 5. Built-In Loop \& Boundary Safeguards



\* \*\*Subtree Boundary Detection:\*\* Automatically stops as soon as the agent returns an OID outside the requested `-RootOID` prefix.

\* \*\*EndOfMibView \& Error Handling:\*\* Terminates cleanly upon receiving `EndOfMibView` (`0x82`) or a non-zero PDU `ErrorStatus`.

\* \*\*Duplicate OID Guard:\*\* Detects non-compliant agents that return the same OID twice in a row and halts with a warning to prevent infinite loops.

\* \*\*Strict ASN.1 TLV Walking:\*\* Parses exact Tag-Length-Value offsets rather than scanning for byte patterns, preventing false matches against community strings or payload bytes.



> \*\*Performance Note:\*\* `Invoke-SnmpV2Walk` reuses a single `UdpClient` socket across the entire walk rather than opening and closing a new socket per OID, keeping subtree traversal fast across high-port-count switches.



