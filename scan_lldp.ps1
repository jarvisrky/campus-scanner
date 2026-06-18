param(
    [string]$ProjectDir = "C:\Users\jarvi\Documents\wireshark-proj",
    [string]$Output = "$env:USERPROFILE\Desktop\portmap.csv",
    [string]$Adapter = "Ethernet",
    [string]$WindowsAdapter = "",
    [int]$Duration = 90,
    [int]$IpWaitSeconds = 20,
    [string]$TsharkPath = "C:\Program Files\Wireshark\tshark.exe",
    [switch]$IncludeOwnLldp,
    [switch]$KeepRaw
)

# Continuous LLDP/CDP port mapper using TShark field extraction.
# v2 fixes PowerShell CSV property names for TShark fields with dots, dynamically checks supported TShark fields,
# and separates the TShark capture adapter from the Windows adapter used for LinkSpeed/IP/Subnet.

$ErrorActionPreference = "Stop"

function Convert-MacToColonLower {
    param([string]$Mac)
    if ([string]::IsNullOrWhiteSpace($Mac)) { return "" }
    $clean = ($Mac -replace '[-:\.]','').ToLower()
    if ($clean.Length -ne 12) { return $Mac.ToLower() }
    return (($clean -split '(.{2})' | Where-Object { $_ }) -join ':')
}

function Get-SubnetId {
    param([string]$IpAddress, [int]$PrefixLength)
    if ([string]::IsNullOrWhiteSpace($IpAddress) -or $PrefixLength -lt 0 -or $PrefixLength -gt 32) { return "" }

    $ipBytes = [System.Net.IPAddress]::Parse($IpAddress).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)

    if ($PrefixLength -eq 0) { $maskInt = [uint32]0 }
    else { $maskInt = ([uint32]::MaxValue -shl (32 - $PrefixLength)) }

    $networkInt = $ipInt -band $maskInt
    $networkBytes = [BitConverter]::GetBytes([uint32]$networkInt)
    [Array]::Reverse($networkBytes)
    return ([System.Net.IPAddress]::new($networkBytes)).ToString() + "/" + $PrefixLength
}

function Get-LocalAdapterInfo {
    param(
        [string]$TsharkAdapterName,
        [string]$WinAdapterName,
        [int]$WaitSeconds = 20
    )

    $adapterObj = $null

    if (-not [string]::IsNullOrWhiteSpace($WinAdapterName)) {
        $adapterObj = Get-NetAdapter -Name $WinAdapterName -ErrorAction SilentlyContinue
    }

    if (-not $adapterObj -and $TsharkAdapterName -notmatch '^\d+$') {
        $adapterObj = Get-NetAdapter -Name $TsharkAdapterName -ErrorAction SilentlyContinue
    }

    if (-not $adapterObj -and $TsharkAdapterName -notmatch '^\d+$') {
        $adapterObj = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
            $_.Status -eq "Up" -and (
                $_.Name -like "*$TsharkAdapterName*" -or
                $_.InterfaceDescription -like "*$TsharkAdapterName*"
            )
        } | Select-Object -First 1
    }

    if (-not $adapterObj) {
        # Prefer a physical/up Ethernet-style adapter over Wi-Fi, VPN, vEthernet, etc.
        $adapterObj = Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -eq "Up" -and $_.HardwareInterface -eq $true } |
            Sort-Object @{Expression={ if ($_.Name -like "*Ethernet*" -or $_.InterfaceDescription -like "*Ethernet*" -or $_.NdisPhysicalMedium -eq 14) {0} else {1} }} |
            Select-Object -First 1
    }

    if (-not $adapterObj) {
        $adapterObj = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    }

    $ipv4 = ""; $prefix = ""; $gateway = ""; $subnet = ""; $ipSource = ""

    if ($adapterObj) {
        # DHCP can lag after moving jacks. Wait briefly for a usable IPv4 address.
        $deadline = (Get-Date).AddSeconds($WaitSeconds)
        do {
            $ipObj = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $adapterObj.ifIndex -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.IPAddress -notlike "169.254.*" -and $_.AddressState -ne "Deprecated" } |
                Sort-Object @{Expression={ if ($_.AddressState -eq "Preferred") {0} else {1} }}, PrefixOrigin |
                Select-Object -First 1

            if ($ipObj) {
                $ipv4 = $ipObj.IPAddress
                $prefix = [string]$ipObj.PrefixLength
                $subnet = Get-SubnetId -IpAddress $ipv4 -PrefixLength ([int]$ipObj.PrefixLength)
                $ipSource = "Get-NetIPAddress"
                break
            }

            Start-Sleep -Seconds 2
        } while ((Get-Date) -lt $deadline)

        # Fallback to Get-NetIPConfiguration if the direct IP call did not return anything.
        if (-not $ipv4) {
            $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapterObj.ifIndex -ErrorAction SilentlyContinue
            if ($ipConfig -and $ipConfig.IPv4Address) {
                $ipv4Obj = $ipConfig.IPv4Address | Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1
                if ($ipv4Obj) {
                    $ipv4 = $ipv4Obj.IPAddress
                    $prefix = [string]$ipv4Obj.PrefixLength
                    $subnet = Get-SubnetId -IpAddress $ipv4 -PrefixLength ([int]$ipv4Obj.PrefixLength)
                    $ipSource = "Get-NetIPConfiguration"
                }
            }
        }

        $route = Get-NetRoute -InterfaceIndex $adapterObj.ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
            Sort-Object RouteMetric |
            Select-Object -First 1
        if ($route) { $gateway = $route.NextHop }
    }

    [PSCustomObject]@{
        AdapterName = if ($adapterObj) { $adapterObj.Name } else { $TsharkAdapterName }
        LinkSpeed   = if ($adapterObj) { $adapterObj.LinkSpeed } else { "" }
        MacAddress  = if ($adapterObj) { Convert-MacToColonLower $adapterObj.MacAddress } else { "" }
        IPv4        = $ipv4
        Prefix      = $prefix
        SubnetID    = $subnet
        Gateway     = $gateway
        IPSource    = $ipSource
    }
}

function First-NonEmpty {
    param([string[]]$Values)
    foreach ($v in $Values) {
        if (-not [string]::IsNullOrWhiteSpace($v)) { return $v.Trim() }
    }
    return ""
}

function Split-FieldValues {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
    return ($Value -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Build-VlanList {
    param($Row)
    $items = New-Object System.Collections.Generic.List[string]

    foreach ($v in (Split-FieldValues $Row.lldp_pvid)) { if ($v) { $items.Add("PVID:$v") } }

    $vlanIds = Split-FieldValues $Row.lldp_vlan_id
    $vlanNames = Split-FieldValues $Row.lldp_vlan_name
    for ($i = 0; $i -lt $vlanIds.Count; $i++) {
        $id = $vlanIds[$i]
        $name = if ($i -lt $vlanNames.Count) { $vlanNames[$i] } else { "" }
        if ($id -and $name) { $items.Add("VLAN:$id ($name)") }
        elseif ($id) { $items.Add("VLAN:$id") }
    }

    foreach ($v in (Split-FieldValues $Row.cdp_native_vlan)) { if ($v) { $items.Add("CDP-native:$v") } }
    foreach ($v in (Split-FieldValues $Row.cdp_voice_vlan)) { if ($v) { $items.Add("CDP-voice:$v") } }
    foreach ($v in (Split-FieldValues $Row.med_vlan_id)) { if ($v) { $items.Add("MED-policy:$v") } }

    return (($items | Select-Object -Unique) -join '; ')
}

function Get-SupportedTsharkFields {
    param([string]$Tshark)
    $set = @{}
    try {
        $lines = & $Tshark -G fields 2>$null
        foreach ($line in $lines) {
            if ($line.StartsWith("F`t")) {
                $parts = $line -split "`t"
                if ($parts.Count -ge 3) { $set[$parts[2]] = $true }
            }
        }
    } catch {}
    return $set
}

function Resolve-Field {
    param($Supported, [string[]]$Names)
    foreach ($name in $Names) {
        if ($Supported.ContainsKey($name)) { return $name }
    }
    return $null
}

function Build-FieldMap {
    param([string]$Tshark)
    $supported = Get-SupportedTsharkFields -Tshark $Tshark

    $wanted = @(
        @{ Alias = "frame_time_epoch"; Names = @("frame.time_epoch") },
        @{ Alias = "eth_src";          Names = @("eth.src") },
        @{ Alias = "lldp_system_name"; Names = @("lldp.tlv.system.name", "lldp.system.name") },
        @{ Alias = "lldp_chassis_id";  Names = @("lldp.chassis.id") },
        @{ Alias = "lldp_port_id";     Names = @("lldp.port.id") },
        @{ Alias = "lldp_port_desc";   Names = @("lldp.port.desc") },
        @{ Alias = "lldp_mgmt_ip";     Names = @("lldp.mgn.addr.ip4", "lldp.mgmt.addr.ip4") },
        @{ Alias = "lldp_pvid";        Names = @("lldp.ieee.802_1.port_vlan.id") },
        @{ Alias = "lldp_vlan_id";     Names = @("lldp.ieee.802_1.vlan.id") },
        @{ Alias = "lldp_vlan_name";   Names = @("lldp.ieee.802_1.vlan.name") },
        @{ Alias = "med_vlan_id";      Names = @("lldp.tia.network_policy.vlan_id") },
        @{ Alias = "cdp_deviceid";     Names = @("cdp.deviceid") },
        @{ Alias = "cdp_system_name";  Names = @("cdp.system_name") },
        @{ Alias = "cdp_portid";       Names = @("cdp.portid") },
        @{ Alias = "cdp_native_vlan";  Names = @("cdp.native_vlan") },
        @{ Alias = "cdp_voice_vlan";   Names = @("cdp.voice_vlan") }
    )

    $map = New-Object System.Collections.Generic.List[object]
    foreach ($w in $wanted) {
        $field = Resolve-Field -Supported $supported -Names $w.Names
        if ($field) {
            $map.Add([PSCustomObject]@{ Alias = $w.Alias; Field = $field })
        }
    }
    return $map
}

function Get-BestNeighborFromTsv {
    param([string]$TsvPath, [string[]]$Headers, [string]$LocalMac, [bool]$IncludeOwn)

    if (-not (Test-Path $TsvPath)) { return $null }
    $rows = Import-Csv -Path $TsvPath -Delimiter "`t" -Header $Headers
    $candidates = New-Object System.Collections.Generic.List[object]

    foreach ($row in $rows) {
        $src = Convert-MacToColonLower $row.eth_src
        if (-not $IncludeOwn -and $LocalMac -and $src -eq $LocalMac) { continue }

        $switch = First-NonEmpty @($row.lldp_system_name, $row.cdp_deviceid, $row.cdp_system_name, $row.lldp_chassis_id)
        $port = First-NonEmpty @($row.lldp_port_id, $row.cdp_portid, $row.lldp_port_desc)
        $portDesc = First-NonEmpty @($row.lldp_port_desc)
        $mgmt = First-NonEmpty @($row.lldp_mgmt_ip)
        $vlans = Build-VlanList $row
        $protocol = if ($row.lldp_system_name -or $row.lldp_port_id -or $row.lldp_chassis_id) { "LLDP" } elseif ($row.cdp_deviceid -or $row.cdp_portid) { "CDP" } else { "" }

        if (-not $switch -and -not $port -and -not $vlans) { continue }

        $score = 0
        if ($switch) { $score += 4 }
        if ($port) { $score += 4 }
        if ($vlans) { $score += 3 }
        if ($mgmt) { $score += 2 }
        if ($portDesc -and $portDesc -ne $port) { $score += 1 }
        if ($protocol -eq "LLDP") { $score += 1 }

        # Prefer actual switch-like info over endpoints that only advertise a MAC as port ID.
        if ($port -match '^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$') { $score -= 2 }
        if ($switch -and $switch -notmatch '^[0-9a-fA-F:.-]+$') { $score += 1 }

        $key = "$switch|$port|$vlans"
        $candidates.Add([PSCustomObject]@{
            Time       = $row.frame_time_epoch
            SourceMAC  = $src
            Protocol   = $protocol
            Switch     = $switch
            Switchport = $port
            PortDesc   = $portDesc
            VLANs      = $vlans
            MgmtIP     = $mgmt
            Score      = $score
            Key        = $key
        })
    }

    if ($candidates.Count -eq 0) { return $null }

    $bestGroup = $candidates |
        Group-Object Key |
        Sort-Object @{ Expression = { $_.Count }; Descending = $true },
                    @{ Expression = { ($_.Group | Measure-Object Score -Maximum).Maximum }; Descending = $true } |
        Select-Object -First 1

    $best = $bestGroup.Group |
        Sort-Object @{ Expression = { $_.Score }; Descending = $true },
                    @{ Expression = { [double]($_.Time -as [double]) }; Descending = $true } |
        Select-Object -First 1

    $best | Add-Member -NotePropertyName EvidenceCount -NotePropertyValue $bestGroup.Count -Force
    $best | Add-Member -NotePropertyName CandidateCount -NotePropertyValue $candidates.Count -Force
    return $best
}

if (-not (Test-Path $TsharkPath)) { throw "TShark not found at: $TsharkPath. Install Wireshark or pass -TsharkPath." }

New-Item -ItemType Directory -Force -Path $ProjectDir | Out-Null
$CaptureDir = Join-Path $ProjectDir "captures"
New-Item -ItemType Directory -Force -Path $CaptureDir | Out-Null

$fieldMap = Build-FieldMap -Tshark $TsharkPath
if ($fieldMap.Count -lt 4) { throw "Could not resolve enough TShark fields. Try updating Wireshark/TShark." }
$headers = @($fieldMap | ForEach-Object { $_.Alias })

Write-Host "TShark LLDP/CDP continuous scanner v3" -ForegroundColor Cyan
Write-Host "Output CSV: $Output" -ForegroundColor Cyan
Write-Host "TShark Adapter: $Adapter | Windows Adapter: $(if ($WindowsAdapter) { $WindowsAdapter } else { 'auto' }) | Duration: $Duration sec | IP wait: $IpWaitSeconds sec" -ForegroundColor Cyan
Write-Host "Type q and press Enter to quit." -ForegroundColor Yellow

if (-not (Test-Path $Output)) {
    [PSCustomObject]@{
        Jack = ""; Switch = ""; switchport = ""; 'VLAN(s)' = ""; LinkSpeed = ""; Adapter = ""; IPv4 = ""; PrefixLength = ""; SubnetID = ""; Gateway = ""; Protocol = ""; MgmtIP = ""; SourceMAC = ""; EvidenceCount = ""; CandidateCount = ""; CaptureFile = ""; ScanTime = ""; IPSource = ""
    } | Export-Csv -Path $Output -NoTypeInformation
}

while ($true) {
    Write-Host ""
    $jack = Read-Host "Jack label"
    if ($jack -match '^(q|quit|exit)$') { break }
    if ([string]::IsNullOrWhiteSpace($jack)) { Write-Host "Blank jack label skipped." -ForegroundColor Yellow; continue }

    Write-Host "Plugged into $jack. Capturing LLDP/CDP for $Duration seconds..." -ForegroundColor Green

    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $safeJack = ($jack -replace '[^a-zA-Z0-9._-]', '_')
    $pcap = Join-Path $CaptureDir "$stamp-$safeJack.pcapng"
    $tsv = Join-Path $CaptureDir "$stamp-$safeJack-fields.tsv"

    $captureArgs = @("-i", $Adapter, "-a", "duration:$Duration", "-f", "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc", "-w", $pcap)
    & $TsharkPath @captureArgs | Out-Null

    $fieldArgs = @("-r", $pcap, "-Y", "lldp or cdp", "-T", "fields")
    foreach ($m in $fieldMap) { $fieldArgs += @("-e", $m.Field) }
    $fieldArgs += @("-E", "header=n", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=;", "-E", "quote=n")

    $raw = & $TsharkPath @fieldArgs 2>&1
    $raw | Set-Content -Path $tsv -Encoding UTF8

    $local = Get-LocalAdapterInfo -TsharkAdapterName $Adapter -WinAdapterName $WindowsAdapter -WaitSeconds $IpWaitSeconds
    $best = Get-BestNeighborFromTsv -TsvPath $tsv -Headers $headers -LocalMac $local.MacAddress -IncludeOwn ([bool]$IncludeOwnLldp)

    if (-not $best) {
        Write-Host "No usable LLDP/CDP neighbor found for $jack, but the raw capture was saved for review." -ForegroundColor Red
        Write-Host "Raw fields: $tsv" -ForegroundColor DarkYellow
        $row = [PSCustomObject]@{ Jack=$jack; Switch=""; switchport=""; 'VLAN(s)'=""; LinkSpeed=$local.LinkSpeed; Adapter=$local.AdapterName; IPv4=$local.IPv4; PrefixLength=$local.Prefix; SubnetID=$local.SubnetID; Gateway=$local.Gateway; Protocol=""; MgmtIP=""; SourceMAC=""; EvidenceCount="0"; CandidateCount="0"; CaptureFile=$pcap; ScanTime=(Get-Date).ToString("s"); IPSource=$local.IPSource }
    } else {
        $row = [PSCustomObject]@{ Jack=$jack; Switch=$best.Switch; switchport=$best.Switchport; 'VLAN(s)'=$best.VLANs; LinkSpeed=$local.LinkSpeed; Adapter=$local.AdapterName; IPv4=$local.IPv4; PrefixLength=$local.Prefix; SubnetID=$local.SubnetID; Gateway=$local.Gateway; Protocol=$best.Protocol; MgmtIP=$best.MgmtIP; SourceMAC=$best.SourceMAC; EvidenceCount=$best.EvidenceCount; CandidateCount=$best.CandidateCount; CaptureFile=$pcap; ScanTime=(Get-Date).ToString("s"); IPSource=$local.IPSource }
    }

    $row | Export-Csv -Path $Output -Append -NoTypeInformation
    Write-Host "Saved:" -ForegroundColor Cyan
    $row | Format-List Jack,Switch,switchport,'VLAN(s)',LinkSpeed,Adapter,IPv4,PrefixLength,SubnetID,Gateway,Protocol,EvidenceCount,CandidateCount

    if (-not $KeepRaw -and $best -and (Test-Path $tsv)) { Remove-Item $tsv -Force -ErrorAction SilentlyContinue }
}

Write-Host "Done. CSV is here: $Output" -ForegroundColor Cyan
