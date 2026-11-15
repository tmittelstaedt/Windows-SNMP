function Invoke-SnmpV2Walk {
    param (
        [Parameter(Mandatory=$true)]
        [string]$TargetIP,
        
        [string]$Community = "public",
        
        [Parameter(Mandatory=$true)]
        [string]$RootOID,
        
        [int]$Port = 161,
        [int]$TimeoutMs = 3000,
        [int]$MaxResults = 10000
    )

    function Encode-BerLength([int]$Length) {
        if ($Length -lt 128) {
            return [byte[]]@($Length)
        }
        $Bytes = [System.Collections.Generic.List[byte]]::new()
        while ($Length -gt 0) {
            $Bytes.Insert(0, [byte]($Length -band 0xFF))
            $Length = $Length -shr 8
        }
        $Bytes.Insert(0, [byte](0x80 -bor $Bytes.Count))
        return $Bytes.ToArray()
    }

    function Encode-BerOid([string]$OidString) {
        $Parts = $OidString.TrimStart('.').Split('.') | ForEach-Object { [uint32]$_ }
        $Encoded = [System.Collections.Generic.List[byte]]::new()
        
        # First two arcs combined: (40 * X) + Y
        $Encoded.Add([byte]((40 * $Parts[0]) + $Parts[1]))
        
        # Subsequent arcs use base-128 VLQ encoding
        for ($i = 2; $i -lt $Parts.Count; $i++) {
            $Val = $Parts[$i]
            if ($Val -eq 0) {
                $Encoded.Add(0x00)
                continue
            }
            $Temp = [System.Collections.Generic.List[byte]]::new()
            while ($Val -gt 0) {
                $Temp.Insert(0, [byte](($Val -band 0x7F) -bor 0x80))
                $Val = $Val -shr 7
            }
            $Temp[$Temp.Count - 1] = $Temp[$Temp.Count - 1] -band 0x7F
            $Encoded.AddRange($Temp)
        }
        
        $LenBytes = Encode-BerLength $Encoded.Count
        return [byte[]]@(0x06) + $LenBytes + $Encoded.ToArray()
    }

    $CleanRoot = $RootOID.TrimStart('.')
    $CurrentOid = $CleanRoot
    $Count = 0

    $UdpClient = New-Object System.Net.Sockets.UdpClient
    $UdpClient.Client.ReceiveTimeout = $TimeoutMs
    $RemoteEndPoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)

    try {
        while ($Count -lt $MaxResults) {
            # Build VarBind: SEQUENCE { CurrentOid, NULL }
            $OidBytes = Encode-BerOid $CurrentOid
            $NullBytes = [byte[]]@(0x05, 0x00)
            $VarBindContent = $OidBytes + $NullBytes
            $VarBind = [byte[]]@(0x30) + (Encode-BerLength $VarBindContent.Length) + $VarBindContent
            $VarBindList = [byte[]]@(0x30) + (Encode-BerLength $VarBind.Length) + $VarBind

            # Build GetNextRequest PDU (Tag 0xA1)
            $ReqId = Get-Random -Minimum 1 -Maximum 32767
            $ReqIdBytes = [byte[]]@(0x02, 0x02, (($ReqId -shr 8) -band 0xFF), ($ReqId -band 0xFF))
            $ErrorStatus = [byte[]]@(0x02, 0x01, 0x00)
            $ErrorIndex  = [byte[]]@(0x02, 0x01, 0x00)
            
            $PduContent = $ReqIdBytes + $ErrorStatus + $ErrorIndex + $VarBindList
            $Pdu = [byte[]]@(0xA1) + (Encode-BerLength $PduContent.Length) + $PduContent

            # Build SNMPv2c Message Header
            $VersionBytes = [byte[]]@(0x02, 0x01, 0x01)
            $CommStringBytes = [System.Text.Encoding]::ASCII.GetBytes($Community)
            $CommBytes = [byte[]]@(0x04) + (Encode-BerLength $CommStringBytes.Length) + $CommStringBytes

            $MessageContent = $VersionBytes + $CommBytes + $Pdu
            $Packet = [byte[]]@(0x30) + (Encode-BerLength $MessageContent.Length) + $MessageContent

            # Send and Receive
            [void]$UdpClient.Send($Packet, $Packet.Length, $TargetIP, $Port)
            $ResponseBytes = $UdpClient.Receive([ref]$RemoteEndPoint)
            
            $Item = Parse-SnmpWalkResponse -Bytes $ResponseBytes

            # Check for SNMP PDU ErrorStatus or EndOfMibView (0x82)
            if ($Item.ErrorStatus -ne 0 -or $Item.Type -eq "0x82") {
                break
            }

            # Stop once the walk exits the requested RootOID subtree
            if ($Item.OID -ne $CleanRoot -and -not $Item.OID.StartsWith("$CleanRoot.")) {
                break
            }

            # Loop guard in case an agent repeats the same OID
            if ($Item.OID -eq $CurrentOid) {
                Write-Warning "Agent returned duplicate OID ($CurrentOid); stopping walk to prevent infinite loop."
                break
            }

            # Emit result object immediately to pipeline
            [PSCustomObject]@{
                OID   = $Item.OID
                Type  = $Item.Type
                Value = $Item.Value
            }

            $CurrentOid = $Item.OID
            $Count++
        }
    }
    catch [System.Net.Sockets.SocketException] {
        Write-Warning "SNMP walk to $TargetIP timed out or failed at OID ${CurrentOid}: $($_.Exception.Message)"
    }
    finally {
        $UdpClient.Close()
    }
}

function Parse-SnmpWalkResponse {
    param ([byte[]]$Bytes)

    function Read-BerTlv([byte[]]$Buf, [int]$Offset) {
        $Tag = $Buf[$Offset]
        $LenByte = $Buf[$Offset + 1]
        if ($LenByte -lt 128) {
            $Len = $LenByte
            $ValStart = $Offset + 2
        } else {
            $NumLenBytes = $LenByte -band 0x7F
            $Len = 0
            for ($i = 0; $i -lt $NumLenBytes; $i++) {
                $Len = ($Len -shl 8) -bor $Buf[$Offset + 2 + $i]
            }
            $ValStart = $Offset + 2 + $NumLenBytes
        }
        return @{
            Tag      = $Tag
            Length   = $Len
            ValStart = $ValStart
            Next     = $ValStart + $Len
        }
    }

    function Decode-BerOid([byte[]]$OidPayload) {
        if ($OidPayload.Length -eq 0) { return "" }
        $Arcs = [System.Collections.Generic.List[uint64]]::new()
        
        # First byte encodes (40 * X) + Y
        $First = [int]$OidPayload[0]
        if ($First -lt 40) {
            $Arcs.Add(0); $Arcs.Add($First)
        } elseif ($First -lt 80) {
            $Arcs.Add(1); $Arcs.Add($First - 40)
        } else {
            $Arcs.Add(2); $Arcs.Add($First - 80)
        }

        # Decode remaining base-128 VLQ arcs
        [uint64]$Val = 0
        for ($i = 1; $i -lt $OidPayload.Length; $i++) {
            $b = $OidPayload[$i]
            $Val = ($Val -shl 7) -bor ($b -band 0x7F)
            if (($b -band 0x80) -eq 0) {
                $Arcs.Add($Val)
                $Val = 0
            }
        }
        return ($Arcs -join ".")
    }

    # Walk exact ASN.1 structure
    $Msg = Read-BerTlv $Bytes 0
    $Pos = $Msg.ValStart

    $Ver  = Read-BerTlv $Bytes $Pos; $Pos = $Ver.Next
    $Comm = Read-BerTlv $Bytes $Pos; $Pos = $Comm.Next

    $Pdu = Read-BerTlv $Bytes $Pos; $Pos = $Pdu.ValStart

    $ReqId  = Read-BerTlv $Bytes $Pos; $Pos = $ReqId.Next
    $ErrSt  = Read-BerTlv $Bytes $Pos; $Pos = $ErrSt.Next
    $ErrIdx = Read-BerTlv $Bytes $Pos; $Pos = $ErrIdx.Next

    $ErrVal = 0
    for ($i = 0; $i -lt $ErrSt.Length; $i++) {
        $ErrVal = ($ErrVal -shl 8) -bor $Bytes[$ErrSt.ValStart + $i]
    }

    $VbList = Read-BerTlv $Bytes $Pos; $Pos = $VbList.ValStart
    $Vb     = Read-BerTlv $Bytes $Pos; $Pos = $Vb.ValStart

    # Decode the returned OID
    $RespOidTlv = Read-BerTlv $Bytes $Pos; $Pos = $RespOidTlv.Next
    $RespOidBytes = $Bytes[$RespOidTlv.ValStart..($RespOidTlv.ValStart + $RespOidTlv.Length - 1)]
    $DecodedOid = Decode-BerOid $RespOidBytes

    # Read the Value TLV
    $ValTlv = Read-BerTlv $Bytes $Pos
    $ValTag = $ValTlv.Tag
    $RawData = if ($ValTlv.Length -gt 0) {
        $Bytes[$ValTlv.ValStart..($ValTlv.ValStart + $ValTlv.Length - 1)]
    } else {
        [byte[]]@()
    }

    $DecodedValue = switch ($ValTag) {
        0x02 { # INTEGER
            [int64]$Num = 0
            foreach ($b in $RawData) { $Num = ($Num -shl 8) -bor $b }
            $Num
        }
        0x04 { # OCTET STRING (Format binary MACs/hex cleanly if non-ASCII bytes exist)
            $IsPrintable = $true
            foreach ($b in $RawData) {
                if (($b -lt 32 -and $b -notin 9, 10, 13) -or $b -gt 126) {
                    $IsPrintable = $false
                    break
                }
            }
            if ($IsPrintable) {
                [System.Text.Encoding]::ASCII.GetString($RawData)
            } else {
                ($RawData | ForEach-Object { $_.ToString("X2") }) -join ":"
            }
        }
        0x05 { "NULL" }
        0x06 { # OBJECT IDENTIFIER value
            Decode-BerOid $RawData
        }
        0x40 { # IpAddress
            ($RawData | ForEach-Object { $_.ToString() }) -join "."
        }
        0x41 { # Counter32
            [uint64]$Num = 0
            foreach ($b in $RawData) { $Num = ($Num -shl 8) -bor $b }
            $Num
        }
        0x42 { # Gauge32
            [uint64]$Num = 0
            foreach ($b in $RawData) { $Num = ($Num -shl 8) -bor $b }
            $Num
        }
        0x43 { # TimeTicks
            [uint64]$Ticks = 0
            foreach ($b in $RawData) { $Ticks = ($Ticks -shl 8) -bor $b }
            [TimeSpan]::FromMilliseconds($Ticks * 10).ToString()
        }
        0x46 { # Counter64
            [uint64]$Num = 0
            foreach ($b in $RawData) { $Num = ($Num -shl 8) -bor $b }
            $Num
        }
        0x80 { "NoSuchObject" }
        0x81 { "NoSuchInstance" }
        0x82 { "EndOfMibView" }
        default { "Raw Hex (Tag 0x$($ValTag.ToString('X2'))): " + ([BitConverter]::ToString($RawData)) }
    }

    return [PSCustomObject]@{
        ErrorStatus = $ErrVal
        OID         = $DecodedOid
        Type        = "0x$($ValTag.ToString('X2'))"
        Value       = $DecodedValue
    }
}
