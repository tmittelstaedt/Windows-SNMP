param(
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$IPAddress = "172.16.3.252",

    [string]$Community = "public",

    [ValidateRange(500, 5000)]
    [int]$Timeout = 1000
)

# OIDs for printer identity info
$OIDs = @(
    @{ Name = "sysName";      OID = ".1.3.6.1.2.1.1.5.0" },
    @{ Name = "sysDescr";     OID = ".1.3.6.1.2.1.1.1.0" },
    @{ Name = "PrinterModel"; OID = ".1.3.6.1.2.1.25.3.2.1.3.1" }
)

try {
    # Create SNMP COM object
    $SNMP = New-Object -ComObject olePrn.OleSNMP -ErrorAction Stop
    $SNMP.Open($IPAddress, $Community, 1, $Timeout)  # SNMPv1 only

    # Query each OID
    $results = foreach ($item in $OIDs) {
        [PSCustomObject]@{
            OIDName = $item.Name
            OID     = $item.OID
            Value   = $SNMP.Get($item.OID)
        }
    }

    $SNMP.Close()

    Write-Host "SNMPv1 PASS on ${IPAddress}" -ForegroundColor Green
    $results | Format-Table -AutoSize
}
catch {
    Write-Host "SNMPv1 FAIL on ${IPAddress} - Error: $($_.Exception.Message)" -ForegroundColor Red
}
