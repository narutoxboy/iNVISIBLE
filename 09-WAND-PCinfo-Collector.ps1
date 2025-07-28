# PowerShell script to collect PC hardware information
# narutoxboy

# Define file paths
$OutputFile = "\\172.16.0.9\Temp\PC\PC-information.txt"
$DebugLog = "$env:TEMP\PC-info-debug.log"
$MaxRetries = 10  # Increased for better concurrency
$RetryDelay = 5   # Increased delay (seconds)

# Function to write to debug log
function Write-DebugLog {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $DebugLog -Append -Encoding utf8 -ErrorAction SilentlyContinue
}

# Function to check if running as admin
function Test-Admin {
    $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
    return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to relaunch script as admin
function Start-Elevated {
    Write-DebugLog "Attempting to relaunch script as admin"
    $ScriptPath = $MyInvocation.ScriptName
    try {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`"" -Verb RunAs -ErrorAction Stop
        Write-DebugLog "Successfully relaunched as admin"
        exit
    }
    catch {
        Write-DebugLog "Failed to relaunch as admin: $_"
        throw "Cannot relaunch script as admin: $_"
    }
}

# Function to parse EDID bytes for monitor information
function Get-StringFromBytes($bytes) {
    $text = ""
    foreach ($b in $bytes) {
        if ($b -eq 0) { break }
        $text += [char]$b
    }
    return $text.Trim()
}

# Function to safely append to the output file
function Append-ToFile {
    param ([string]$Line)
    $Attempts = 0
    Write-DebugLog "Attempting to append to $OutputFile"
    while ($Attempts -lt $MaxRetries) {
        try {
            # Write header if file doesn't exist
            if (-not (Test-Path $OutputFile)) {
                Write-DebugLog "Writing header to $OutputFile"
                "STT||DateTime||ComputerName||CPUName||RAM(GB)||DISK-C(GB)||DISK-D(GB)||GPUName||Mainboard||IPAddress||Monitors||NetworkAdapters" | Out-File -FilePath $OutputFile -Encoding utf8 -ErrorAction Stop
            }

            # Calculate sequence number
            $SequenceNumber = (Get-Content -Path $OutputFile | Measure-Object -Line).Lines
            if ($SequenceNumber -eq 1) { $SequenceNumber = 1 } # Start with 1 if only header exists
            else { $SequenceNumber = $SequenceNumber } # Increment for new line (excluding header)

            # Prepend sequence number to the line
            $LineWithSequence = "$SequenceNumber||$Line"

            # Append the line with sequence number
            $LineWithSequence | Out-File -FilePath $OutputFile -Append -Encoding utf8 -ErrorAction Stop
            Write-DebugLog "Successfully appended line with sequence $SequenceNumber to $OutputFile"
            return $true
        }
        catch {
            $Attempts++
            Write-DebugLog "Write attempt $Attempts failed: $_"
            if ($Attempts -eq $MaxRetries) {
                Write-DebugLog "Failed to append to $OutputFile after $MaxRetries attempts"
                return $false
            }
            Start-Sleep -Seconds $RetryDelay
        }
    }
    return $false
}

Write-Host "================================================" -ForegroundColor Yellow
Write-Host "Dang kiem tra thong tin phan cung....." -ForegroundColor Red
Write-Host "------------------------------------------------" -ForegroundColor Yellow
Write-Host "Hoan tat kiem tra thong tin phan cung." -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Yellow
# Main script
Write-DebugLog "Script started"
try {
    # Log environment details
    $PSVersion = $PSVersionTable.PSVersion.ToString()
    $User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-DebugLog "PowerShell version: $PSVersion"
    Write-DebugLog "Running as user: $User"

    # Check and set execution policy
    $Policy = Get-ExecutionPolicy -Scope CurrentUser
    Write-DebugLog "Execution policy: $Policy"
    if ($Policy -eq "Restricted") {
        Write-DebugLog "Execution policy is Restricted. Attempting to set to RemoteSigned"
        try {
            if (-not (Test-Admin)) {
                Write-DebugLog "Not running as admin. Requesting elevation to set execution policy"
                Start-Elevated
            }
            Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force -ErrorAction Stop
            Write-DebugLog "Successfully set ExecutionPolicy to RemoteSigned"
        }
        catch {
            Write-DebugLog "Failed to set ExecutionPolicy: $_"
            throw "Cannot set ExecutionPolicy to RemoteSigned: $_"
        }
    }

    # Check network share accessibility
    $SharePath = Split-Path $OutputFile -Parent
    Write-DebugLog "Checking network share: $SharePath"
    if (-not (Test-Path $SharePath)) {
        Write-DebugLog "Network share test failed. Attempting with credentials."
        throw "Cannot access network share $SharePath. Check permissions or network connectivity."
    }

    # Initialize result object
    $Result = [PSCustomObject]@{
        DateTime          = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        ComputerName      = "Unknown"
        CPUName           = "Unknown"
        RAMGB             = "Unknown"
        DriveC_CapacityGB = "Unknown"
        DriveD_CapacityGB = "Unknown"
        GPUName           = "Unknown"
        MainboardModel    = "Unknown"
        IPAddress         = "Unknown"
        Monitors          = @()
        NetworkAdapters   = @()
    }

    Write-DebugLog "Collecting system information"
    # Collect system information
    try {
        # Computer Name
        try {
            $Result.ComputerName = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).Name
            Write-DebugLog "Collected ComputerName: $($Result.ComputerName)"
        }
        catch {
            Write-DebugLog "Failed to collect ComputerName: $_"
            $Result.ComputerName = "Unknown"
        }

        # CPU Name
        try {
            $Result.CPUName = (Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1).Name.Trim()
            Write-DebugLog "Collected CPUName: $($Result.CPUName)"
        }
        catch {
            Write-DebugLog "Failed to collect CPUName: $_"
            $Result.CPUName = "Unknown"
        }

        # RAM (convert bytes to GB)
        try {
           #$Result.RAMGB = [math]::Round((Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory / 1GB, 2)
			$Result.RAMGB = [math]::Floor((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB) + 1
            Write-DebugLog "Collected RAMGB: $($Result.RAMGB)"
        }
        catch {
            Write-DebugLog "Failed to collect RAMGB: $_"
            $Result.RAMGB = "Unknown"
        }

		# Drive C: and D: Capacity (in GB)
		try {
			$LogicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop | Where-Object { $_.DeviceID -in @("C:", "D:") }
			$DriveC = $LogicalDisks | Where-Object { $_.DeviceID -eq "C:" }
			$Result.DriveC_CapacityGB = if ($DriveC) { [math]::Round($DriveC.Size / 1GB, 0) } else { "0" }
			Write-DebugLog "Collected DriveC_CapacityGB: $($Result.DriveC_CapacityGB)"
			$DriveD = $LogicalDisks | Where-Object { $_.DeviceID -eq "D:" }
			$Result.DriveD_CapacityGB = if ($DriveD) { [math]::Round($DriveD.Size / 1GB, 0) } else { "0" }
			Write-DebugLog "Collected DriveD_CapacityGB: $($Result.DriveD_CapacityGB)"
		}
		catch {
			Write-DebugLog "Failed to collect drive capacities: $_"
			$Result.DriveC_CapacityGB = "0"
			$Result.DriveD_CapacityGB = "0"
		}

        # GPU Name
        try {
            $VideoController = Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop | Select-Object -First 1
            $Result.GPUName = if ($VideoController) { $VideoController.Name.Trim() } else { "None" }
            Write-DebugLog "Collected GPUName: $($Result.GPUName)"
        }
        catch {
            Write-DebugLog "Failed to collect GPUName: $_"
            $Result.GPUName = "None"
        }

        # Mainboard Model
        try {
            $Mainboard = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction Stop
            $Result.MainboardModel = if ($Mainboard.Product) { $Mainboard.Product.Trim() } else { "Unknown" }
            Write-DebugLog "Collected MainboardModel: $($Result.MainboardModel)"
        }
        catch {
            Write-DebugLog "Failed to collect MainboardModel: $_"
            $Result.MainboardModel = "Unknown"
        }

        # IP Address (first enabled IPv4)
        try {
            $NetworkConfig = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction Stop | Where-Object { $_.IPEnabled -and $_.IPAddress }
            $IPv4 = $NetworkConfig | Select-Object -ExpandProperty IPAddress | Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' } | Select-Object -First 1
            $Result.IPAddress = if ($IPv4) { $IPv4 } else { "None" }
            Write-DebugLog "Collected IPAddress: $($Result.IPAddress)"
        }
        catch {
            Write-DebugLog "Failed to collect IPAddress: $_"
            $Result.IPAddress = "None"
        }

        # Collect Monitors
        try {
            $seenMonitors = @{}
            $monitors = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY"
            foreach ($monitor in $monitors) {
                $subkeys = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY\$($monitor.PSChildName)"
                foreach ($sub in $subkeys) {
                    $edidPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY\$($monitor.PSChildName)\$($sub.PSChildName)\Device Parameters"
                    $edid = Get-ItemProperty -Path $edidPath -Name "EDID" -ErrorAction SilentlyContinue
                    if ($edid) {
                        $bytes = $edid.EDID
                        # Manufacture date
                        $week = $bytes[16]
                        $year = 1990 + $bytes[17]
                        $month = [math]::Ceiling($week / 4.3)
                        $month = "{0:00}" -f $month
                        # Model + Serial from descriptor blocks
                        $model = ""
                        $serial = ""
                        for ($i = 54; $i -le 125; $i += 18) {
                            if ($bytes[$i] -eq 0x00 -and $bytes[$i+1] -eq 0x00 -and $bytes[$i+2] -eq 0x00 -and $bytes[$i+3] -eq 0xFC) {
                                $model = Get-StringFromBytes $bytes[($i+5)..($i+17)]
                            }
                            elseif ($bytes[$i] -eq 0x00 -and $bytes[$i+1] -eq 0x00 -and $bytes[$i+2] -eq 0x00 -and $bytes[$i+3] -eq 0xFF) {
                                $serial = Get-StringFromBytes $bytes[($i+5)..($i+17)]
                            }
                        }
                        $key = "$model|$serial"
                        if (-not $seenMonitors.ContainsKey($key)) {
                            $seenMonitors[$key] = $true
                            $monitorInfo = [PSCustomObject]@{
                                Model  = $model
                                Serial = $serial
                                Date   = "$month/$year"
                            }
                            $Result.Monitors += $monitorInfo
                        }
                    }
                }
            }
            Write-DebugLog "Collected Monitors: $($Result.Monitors.Count)"
        }
        catch {
            Write-DebugLog "Failed to collect Monitors: $_"
        }

        # Collect NetworkAdapters
        try {
            $netAdapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' }
            foreach ($adapter in $netAdapters) {
                $name = $adapter.InterfaceDescription
                $linkSpeed = $adapter.LinkSpeed.ToString()
                # Convert linkSpeed to Mbps
                if ($linkSpeed -match '([\d.]+)\s*(\w+)') {
                    $speedValue = [double]$matches[1]
                    $unit = $matches[2].ToLower()
                    switch ($unit) {
                        'gbps' { $speedMbps = $speedValue * 1000 }
                        'mbps' { $speedMbps = $speedValue }
                        default { $speedMbps = 'Unknown' }
                    }
                } else {
                    $speedMbps = 'Unknown'
                }
                $adapterInfo = [PSCustomObject]@{
                    Name  = $name
                    Speed = $speedMbps
                }
                $Result.NetworkAdapters += $adapterInfo
            }
            Write-DebugLog "Collected NetworkAdapters: $($Result.NetworkAdapters.Count)"
        }
        catch {
            Write-DebugLog "Failed to collect NetworkAdapters: $_"
        }
    }
    catch {
        Write-DebugLog "Failed to collect system information: $_"
        throw "Failed to collect system information: $_"
    }

    # Format output line for file
    $MonitorsString = ($Result.Monitors | ForEach-Object { "$($_.Model),$($_.Serial),$($_.Date)" }) -join ";"
    $NetworkAdaptersString = ($Result.NetworkAdapters | ForEach-Object { "$($_.Name),$($_.Speed)" }) -join ";"
    $OutputLine = "$($Result.DateTime)||$($Result.ComputerName)||$($Result.CPUName)||$($Result.RAMGB)||$($Result.DriveC_CapacityGB)||$($Result.DriveD_CapacityGB)||$($Result.GPUName)||$($Result.MainboardModel)||$($Result.IPAddress)||$MonitorsString||$NetworkAdaptersString"
    Write-DebugLog "Formatted output line: $OutputLine"

    # Display formatted output in console
	Write-Host "                    -o-X-o-" -ForegroundColor Green
    Write-Host "      WAND - THONG TIN PHAN CUNG MAY TINH" -ForegroundColor Cyan
	Write-Host "                    -o-X-o-" -ForegroundColor Green
    Write-Host "DATE - TIME            :     $($Result.DateTime)" -ForegroundColor Blue
    Write-Host "TEN NHAN VIEN          :     $($Result.ComputerName)" -ForegroundColor Green
	Write-Host "------------------------------------------------" -ForegroundColor Yellow
    Write-Host "TEN CPU                :  $($Result.CPUName)"
    Write-Host "DUNG LUONG RAM         :  $($Result.RAMGB) GB" -ForegroundColor DarkGray
    Write-Host "DUNG LUONG O C         :  $($Result.DriveC_CapacityGB) GB"
    Write-Host "DUNG LUONG O D         :  $($Result.DriveD_CapacityGB) GB" -ForegroundColor DarkGray
    Write-Host "TEN GPU                :  $($Result.GPUName)"
    Write-Host "TEN MAINBOARD          :  $($Result.MainboardModel)" -ForegroundColor DarkGray
	if ($Result.NetworkAdapters.Count -gt 0) {
		foreach ($adapter in $Result.NetworkAdapters) {
	Write-Host "TOC DO MANG            :  $($adapter.Speed) Mbps"
        }	
	}	
    Write-Host "DIA CHI IP             :  $($Result.IPAddress)" -ForegroundColor DarkGray


    Write-DebugLog "Displayed formatted output to console"

    if ($Result.Monitors.Count -gt 0) {
        Write-Host "============== THONG TIN MAN HINH ==============" -ForegroundColor Cyan
        foreach ($monitor in $Result.Monitors) {
            Write-Host "MAN HINH               :  $($monitor.Model)" -ForegroundColor Green
            Write-Host "Serial                 :  $($monitor.Serial)"
            Write-Host "Date                   :  $($monitor.Date)"
            Write-Host "------------------------------------------------" -ForegroundColor Yellow
        }
        Write-Host ""
    }

#    if ($Result.NetworkAdapters.Count -gt 0) {
#        Write-Host "============ THONG TIN CARD MANG ===========" -ForegroundColor Red
#        foreach ($adapter in $Result.NetworkAdapters) {
#            Write-Host "TEN CARD MANG  :  $($adapter.Name)" -ForegroundColor Green
#            Write-Host "TOC DO MANG    :  $($adapter.Speed) Mbps"
#            Write-Host "--------------------------------------------"
#        }
#        Write-Host ""
#    }

    # Append to file
    $Success = Append-ToFile -Line $OutputLine
    if (-not $Success) {
        Write-DebugLog "Writing to local fallback: $env:TEMP\PC-information.txt"
        $OutputLine | Out-File -FilePath "$env:TEMP\PC-information.txt" -Append -Encoding utf8
        Write-Host "Failed to write to network share. Saved to $env:TEMP\PC-information.txt" -ForegroundColor Yellow
    }

    # Prompt for exit (interactive mode only)
		Write-Host "================================================" -ForegroundColor Yellow
    if ($Host.Name -eq "ConsoleHost") {
		Write-Host "Boi den va bam phim ENTER de copy Serial, Date"
        Write-Host "Bam phim ENTER de thoat..." -NoNewline -ForegroundColor Green
        $null = Read-Host
        Write-DebugLog "Displayed exit prompt and received Enter"
    }
    else {
        Write-DebugLog "Non-interactive mode, skipping exit prompt"
    }
}
catch {
    Write-DebugLog "Script failed: $_"
    Write-Error "Error: $_"
    Write-Host "Script failed. Check $DebugLog for details. Press any key to continue..." -ForegroundColor Red
    if ($Host.Name -eq "ConsoleHost") {
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Write-DebugLog "Paused for key press on error"
    }
}
finally {
    Write-DebugLog "Script completed"
    # Pause for both interactive and non-interactive modes on error
    if ($Error -or $Host.Name -eq "ConsoleHost") {
        Write-Host "Press ENTER to exit..." -ForegroundColor Yellow
        $null = [Console]::ReadKey($true)
        Write-DebugLog "Paused for key press"
    }
}