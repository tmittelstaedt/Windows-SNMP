\# Invoke-SnmpV2Get.ps1



A pure PowerShell implementation of an \*\*SNMPv2c GET\*\* client built on native .NET sockets (`System.Net.Sockets.UdpClient`) and custom ASN.1 BER encoding/decoding. 



It requires \*\*zero third-party modules, external binaries, or compiled DLLs\*\*, making it ideal for locked-down Windows environments where unsigned or self-signed executables are blocked by Smart App Control or WDAC.



\---



\## 1. Prerequisites \& Loading Into Your Session



Before calling `Invoke-SnmpV2Get`, you must handle two PowerShell session requirements: \*\*Execution Policy\*\* and \*\*Dot-Sourcing\*\*.



\### Step A: Allow Script Execution in the Current Session

Windows clients default to the `Restricted` execution policy, which blocks `.ps1` files from loading. Run the following command to bypass the policy for your \*\*current PowerShell window only\*\* (this automatically resets when you close the terminal):



```powershell

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

```



\### Step B: Dot-Source the Script File

Because `Invoke-SnmpV2Get.ps1` defines reusable functions (`Invoke-SnmpV2Get` and `Parse-SnmpResponse`) rather than executing inline, you must \*\*dot-source\*\* the script using a leading period and space (`. `) so the functions stay loaded in your active session scope:



```powershell

. C:\\scripts\\Invoke-SnmpV2Get.ps1

```



> \*\*Warning:\*\* Running `.\\Invoke-SnmpV2Get.ps1` without the leading `. ` executes the file in a temporary child scope and immediately discards the functions when the script exits, resulting in a \*"term is not recognized"\* error.



\### Required .NET Assemblies

All required classes (`System.Net.Sockets.UdpClient`, `System.Net.IPEndPoint`, `System.Text.Encoding`, and `System.Collections.Generic.List<byte>`) are built into standard Windows PowerShell 5.1 and PowerShell 7+. No `Add-Type` calls or external module imports are needed.



\---



\## 2. Parameters



| Parameter | Type | Required | Default | Description |

| :--- | :--- | :---: | :--- | :--- |

| `-TargetIP` | `\[string]` | Yes | — | IPv4 address of the target SNMP agent (e.g., `"172.16.1.2"`). |

| `-OID` | `\[string]` | Yes | — | Numeric Object Identifier to query (leading dot optional, e.g., `"1.3.6.1.2.1.1.5.0"`). |

| `-Community` | `\[string]` | No | `"public"` | SNMPv2c read-only community string. |

| `-Port` | `\[int]` | No | `161` | Target UDP port for SNMP queries. |

| `-TimeoutMs` | `\[int]` | No | `3000` | UDP socket receive timeout in milliseconds. |



\---



\## 3. Usage Examples



\### Single OID Query

```powershell

$Result = Invoke-SnmpV2Get -TargetIP "172.16.1.2" -Community "public" -OID "1.3.6.1.2.1.1.5.0"

$Result

```



\### Multi-OID Query Loop (System Information)

Query multiple standard MIB-2 variables (`sysName`, `sysDescr`, and `sysUpTime`) and format the results into a clean PowerShell table:



```powershell

\# 1. Prepare session and dot-source the script

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

. C:\\scripts\\Invoke-SnmpV2Get.ps1



\# 2. Define target OIDs

$Oids = @{

&#x20;   "sysName"   = "1.3.6.1.2.1.1.5.0"

&#x20;   "sysDescr"  = "1.3.6.1.2.1.1.1.0"

&#x20;   "sysUpTime" = "1.3.6.1.2.1.1.3.0"

}



\# 3. Query each OID and output structured objects

foreach ($Name in $Oids.Keys) {

&#x20;   $Result = Invoke-SnmpV2Get -TargetIP "172.16.1.2" -Community "public" -OID $Oids\[$Name]

&#x20;   \[PSCustomObject]@{

&#x20;       Variable = $Name

&#x20;       OID      = $Result.OID

&#x20;       Type     = $Result.Type

&#x20;       Value    = $Result.Value

&#x20;   }

}

```



\#### Sample Output

```text

Variable  OID               Type Value

\--------  ---               ---- -----

sysDescr  1.3.6.1.2.1.1.1.0 0x04 GS724TS

sysUpTime 1.3.6.1.2.1.1.3.0 0x43 6.00:15:48

sysName   1.3.6.1.2.1.1.5.0 0x04 switch.example.com

```



\---



\## 4. Supported ASN.1 / SNMP Data Types



The built-in `Parse-SnmpResponse` decoder automatically translates the following BER tags:



| BER Tag | SNMP Type | PowerShell Output Format |

| :--- | :--- | :--- |

| `0x02` | `INTEGER` | `\[int64]` |

| `0x04` | `OCTET STRING` | `\[string]` (ASCII decoded) |

| `0x05` | `NULL` | `"NULL"` |

| `0x40` | `IpAddress` | Dotted-quad `\[string]` (e.g., `172.16.1.2`) |

| `0x41` | `Counter32` | `\[uint64]` |

| `0x42` | `Gauge32` | `\[uint64]` |

| `0x43` | `TimeTicks` | Formatted `\[TimeSpan]` string (`d.hh:mm:ss`) |

| `0x46` | `Counter64` | `\[uint64]` |

| `0x80` / `0x81` | `NoSuchObject` / `NoSuchInstance` | Descriptive status string |

| \*Other\* | Unhandled Tag | `Raw Hex (Tag 0xXX): AA-BB-...` |



> \*\*Note on Agent Compatibility:\*\* This script uses strict ASN.1 Tag-Length-Value (TLV) structure walking rather than byte-pattern scanning, ensuring reliable parsing regardless of community string length or payload contents.



