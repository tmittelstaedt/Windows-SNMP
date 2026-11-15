# SNMP Printer Connectivity Test Script

This PowerShell script uses the legacy `olePrn.OleSNMP` COM object to test SNMP connectivity to a printer.  
It queries standard SNMP OIDs to confirm that SNMP is enabled and responding on the target device.

## Purpose
- Quickly verify SNMP connectivity to a printer.
- Retrieve basic device information such as `sysName` and `sysDescr`.
- Confirm that SNMPv1 is working on the destination printer.

## Important Notes
The `olePrn.OleSNMP` COM object only supports SNMPv1-style queries.  
The third parameter in `.Open()` is labeled as "version", but:

- `1` = SNMPv1  
- `2` = **Extended timeout handling**, NOT true SNMPv2c  

It does not implement SNMPv2c features such as bulk get or 64-bit counters.

> This COM object is legacy and may not be available on all Windows systems.  
> It is primarily designed for printer SNMP queries and is not really intended for general SNMP device management.

## Default Settings
- Default IP Address: `172.16.3.252`
- Default Community String: `public`
- Default Timeout: `1000 ms`
- SNMP Version Parameter: `1` (SNMPv1)

## Queried OIDs
| OID                  | Name     | Description |
|----------------------|----------|-------------|
| `.1.3.6.1.2.1.1.5.0` | sysName  | Device name or hostname. |
| `.1.3.6.1.2.1.1.1.0` | sysDescr | Device description, often includes model and firmware version. |

## Example Usage
```powershell
.\Test-Basic-Get.ps1
