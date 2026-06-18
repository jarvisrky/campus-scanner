<#
scan_lldp_loop_fixed.ps1

Continuous LLDP jack scanner for Windows.
This version is pinned to your project folder by default so it does not matter
what folder PowerShell starts in.

Default project folder:
  C:\Users\jarvi\Documents\wireshark-proj

Put lldp_to_csv_plus.py in that folder.
Run from anywhere with:
  & "C:\Users\jarvi\Documents\wireshark-proj\scan_lldp_loop_fixed.ps1"
#>

param(
    [string]$ProjectFolder = "C:\Users\jarvi\Documents\wireshark-proj",
    [string]$Output = "$env:USERPROFILE\Desktop\portmap.csv",
    [string]$Adapter = "Ethernet",
    [int]$Duration = 45,
    [string]$Tshark = "C:\Program Files\Wireshark\tshark.exe",
    [string]$CaptureFolder = "",
    [switch]$KeepCaptures
)

function Write-Section($Text) {
    Write-Host ""
    Write-Host "==== $Text ====" -ForegroundColor Cyan
}

function Assert-PathExists($Path, $FriendlyName) {
    if (!(Test-Path -LiteralPath $Path)) {
        Write-Host "$FriendlyName not found: $Path" -ForegroundColor Red
        return $false
    }
    return $true
}

function Wait-ForAdapterUp($AdapterName) {
    Write-Host "Checking adapter '$AdapterName'..."
    while ($true) {
        try {
            $adapterInfo = Get-NetAdapter -Name $AdapterName -ErrorAction Stop
            if ($adapterInfo.Status -eq "Up") {
                Write-Host "Adapter is UP. Link speed: $($adapterInfo.LinkSpeed)" -ForegroundColor Green
                return
            }
            Write-Host "Adapter status is '$($adapterInfo.Status)'. Plug into the jack now, or press Ctrl+C to stop..."
        }
        catch {
            Write-Host "Could not find adapter '$AdapterName'. Check the adapter name." -ForegroundColor Yellow
            Write-Host "Available adapters:"
            Get-NetAdapter | Select-Object Name, Status, LinkSpeed | Format-Table -AutoSize
            throw
        }
        Start-Sleep -Seconds 2
    }
}

function Get-LastCsvRow($CsvPath) {
    if (Test-Path -LiteralPath $CsvPath) {
        try {
            $rows = Import-Csv -LiteralPath $CsvPath
            if ($rows.Count -gt 0) {
                return $rows[-1]
            }
        }
        catch {
            return $null
        }
    }
    return $null
}

# Resolve project paths.
$ProjectFolder = [System.IO.Path]::GetFullPath($ProjectFolder)
$PythonScript = Join-Path $ProjectFolder "lldp_to_csv_plus.py"

if ([string]::IsNullOrWhiteSpace($CaptureFolder)) {
    $CaptureFolder = Join-Path $ProjectFolder "captures"
}

# Ensure project/capture folders exist and switch into the project folder.
New-Item -ItemType Directory -Force -Path $ProjectFolder | Out-Null
New-Item -ItemType Directory -Force -Path $CaptureFolder | Out-Null
Set-Location -LiteralPath $ProjectFolder

Write-Section "LLDP Continuous Jack Scanner"
Write-Host "Project folder: $ProjectFolder"
Write-Host "Parser script:  $PythonScript"
Write-Host "Output CSV:     $Output"
Write-Host "Adapter:        $Adapter"
Write-Host "Duration:       $Duration seconds per jack"
Write-Host "Captures:       $CaptureFolder"
Write-Host ""
Write-Host "Type the jack label each time, or type q to quit."
Write-Host "Tip: A barcode scanner that types text + Enter works here."

if (!(Assert-PathExists $Tshark "TShark")) {
    Write-Host "Install Wireshark, or pass the correct path with -Tshark." -ForegroundColor Yellow
    exit 1
}

if (!(Assert-PathExists $PythonScript "Python parser script")) {
    Write-Host "lldp_to_csv_plus.py must be in: $ProjectFolder" -ForegroundColor Yellow
    Write-Host "Current files in project folder:" -ForegroundColor Yellow
    Get-ChildItem -LiteralPath $ProjectFolder | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
    exit 1
}

# Quick check that Python is available.
$pythonOk = $false
try {
    $pythonVersion = python --version 2>&1
    if ($LASTEXITCODE -eq 0) { $pythonOk = $true }
} catch { $pythonOk = $false }

if (-not $pythonOk) {
    Write-Host "Python command was not found. Install Python or add it to PATH." -ForegroundColor Red
    exit 1
}

$scanNumber = 1
while ($true) {
    Write-Section "Scan $scanNumber"
    $Jack = Read-Host "Jack label"

    if ([string]::IsNullOrWhiteSpace($Jack)) {
        Write-Host "Blank label skipped." -ForegroundColor Yellow
        continue
    }

    if ($Jack.Trim().ToLower() -in @("q", "quit", "exit", "done")) {
        Write-Host "Stopping. CSV saved at: $Output" -ForegroundColor Green
        break
    }

    Wait-ForAdapterUp $Adapter

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeJack = ($Jack -replace '[^a-zA-Z0-9_-]+', '_').Trim('_')
    if ([string]::IsNullOrWhiteSpace($safeJack)) { $safeJack = "jack" }
    $TempCapture = Join-Path $CaptureFolder "lldp_${timestamp}_${safeJack}.pcapng"

    Write-Host "Capturing LLDP for $Duration seconds..." -ForegroundColor Cyan
    & $Tshark -i $Adapter -a "duration:$Duration" -f "ether proto 0x88cc" -w $TempCapture

    if (!(Test-Path -LiteralPath $TempCapture)) {
        Write-Host "Capture was not created. Check your adapter name with:" -ForegroundColor Red
        Write-Host "  & `"$Tshark`" -D"
        continue
    }

    $captureSize = (Get-Item -LiteralPath $TempCapture).Length
    if ($captureSize -lt 200) {
        Write-Host "Capture file is very small. LLDP may not have appeared during the capture window." -ForegroundColor Yellow
    }

    Write-Host "Parsing and appending to CSV..." -ForegroundColor Cyan
    python $PythonScript $TempCapture -o $Output --jack $Jack --append --adapter $Adapter

    if ($LASTEXITCODE -ne 0) {
        Write-Host "Parser returned an error. Capture kept at: $TempCapture" -ForegroundColor Red
        continue
    }

    $last = Get-LastCsvRow $Output
    if ($null -ne $last) {
        Write-Host "Saved row:" -ForegroundColor Green
        $last | Format-List Jack, Switch, switchport, 'VLAN(s)', LinkSpeed, IPv4, SubnetID, Gateway
    }
    else {
        Write-Host "Row appended, but could not preview the CSV." -ForegroundColor Yellow
    }

    if (-not $KeepCaptures) {
        Remove-Item -LiteralPath $TempCapture -ErrorAction SilentlyContinue
    }
    else {
        Write-Host "Capture kept: $TempCapture"
    }

    Write-Host "Move to the next jack/port." -ForegroundColor Cyan
    $scanNumber++
}
