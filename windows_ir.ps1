# INCIDENT RESPONSE DATA COLLECTION SCRIPT
# Requires Administrator privileges for full functionality

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires Administrator privileges for complete data collection."
    Write-Host "Some features may be limited. Consider running as Administrator." -ForegroundColor Yellow
}

# Set path to Desktop and IR results folder
$desktopPath = [Environment]::GetFolderPath("Desktop")
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$folderPath = Join-Path -Path $desktopPath -ChildPath "IR_results_$timestamp"

# Create timestamped folder
if (!(Test-Path -Path $folderPath)) {
    New-Item -ItemType Directory -Path $folderPath | Out-Null
}

Write-Host "=== INCIDENT RESPONSE DATA COLLECTION ===" -ForegroundColor Cyan
Write-Host "Output Directory: $folderPath" -ForegroundColor Green
Write-Host ""

# Enhanced file paths with better organization
$systemFolder = Join-Path -Path $folderPath -ChildPath "System"
$networkFolder = Join-Path -Path $folderPath -ChildPath "Network"
$securityFolder = Join-Path -Path $folderPath -ChildPath "Security"
$processFolder = Join-Path -Path $folderPath -ChildPath "Processes"

# Create subfolders
@($systemFolder, $networkFolder, $securityFolder, $processFolder) | ForEach-Object {
    if (!(Test-Path $_)) { New-Item -ItemType Directory -Path $_ | Out-Null }
}

# File Paths - organized by category
$systemCsvPath = Join-Path -Path $systemFolder -ChildPath "SystemData.csv"
$computerInfoTxtPath = Join-Path -Path $systemFolder -ChildPath "ComputerInfo.txt"
$hotfixCsvPath = Join-Path -Path $systemFolder -ChildPath "HotFixes.csv"
$recentModifiedFilesPath = Join-Path -Path $systemFolder -ChildPath "Recently_Modified_System_Files.txt"
$recentInstalledProgramsPath = Join-Path -Path $systemFolder -ChildPath "Recently_Installed_Programs.txt"
$startupProgramsTxtPath = Join-Path -Path $systemFolder -ChildPath "StartupPrograms.html"

$activeTcpCsvPath = Join-Path -Path $networkFolder -ChildPath "Active_TCP_Connections.csv"
$networkTxtPath = Join-Path -Path $networkFolder -ChildPath "Network_Configuration.txt"
$networkNeighborsTxtPath = Join-Path -Path $networkFolder -ChildPath "Network_Neighbors.txt"
$dnsCacheTxtPath = Join-Path -Path $networkFolder -ChildPath "DNS_Cache.txt"
$firewallRulesPath = Join-Path -Path $networkFolder -ChildPath "Firewall_Rules.txt"

$eventsCsvPath = Join-Path -Path $securityFolder -ChildPath "System_EventLogs.csv"
$securityEventsCsvPath = Join-Path -Path $securityFolder -ChildPath "Security_EventLogs.csv"
$scheduledTasksTxtPath = Join-Path -Path $securityFolder -ChildPath "Scheduled_Tasks.txt"
$groupPolicySettingsXmlPath = Join-Path -Path $securityFolder -ChildPath "Group_Policy_Settings.xml"
$localUsersPath = Join-Path -Path $securityFolder -ChildPath "Local_Users_Groups.txt"

$processesTxtPath = Join-Path -Path $processFolder -ChildPath "Running_Processes.csv"
$servicesTxtPath = Join-Path -Path $processFolder -ChildPath "Services.csv"
$wmiPersistencePath = Join-Path -Path $securityFolder -ChildPath "WMI_Persistence_Check.txt"

# Used Values
$fullTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$computer = $env:COMPUTERNAME
$user = $env:USERNAME

Write-Host "Starting data collection..." -ForegroundColor Green

# Function to safely execute commands and handle errors
function Invoke-SafeCommand {
    param(
        [scriptblock]$Command,
        [string]$Description,
        [string]$OutputPath = $null
    )
    
    Write-Host "Collecting: $Description" -ForegroundColor Yellow
    try {
        $result = & $Command
        if ($OutputPath -and $result) {
            $result | Out-File -FilePath $OutputPath -Encoding utf8
        }
        Write-Host "✓ $Description - Complete" -ForegroundColor Green
        return $result
    }
    catch {
        Write-Warning "✗ Failed to collect $Description`: $($_.Exception.Message)"
        return $null
    }
}

# ENHANCED SYSTEM DATA COLLECTION
Write-Host "`n=== SYSTEM INFORMATION ===" -ForegroundColor Cyan

# System Data (Enhanced CSV with more details)
Invoke-SafeCommand -Description "System Configuration" -Command {
    $systemData = @()
    $systemData += '"Timestamp","ComputerName","Username","Domain","OS","Architecture","TotalRAM_GB","InterfaceName","IPv4Address","MACAddress"'
    
    $computerInfo = Get-ComputerInfo
    $totalRAM = [math]::Round($computerInfo.TotalPhysicalMemory / 1GB, 2)
    $adapters = Get-NetIPConfiguration | Where-Object { $_.IPv4Address }
    
    foreach ($adapter in $adapters) {
        $interfaceName = $adapter.InterfaceAlias
        $ipAddress = $adapter.IPv4Address.IPAddress
        $macAddress = (Get-NetAdapter -InterfaceAlias $interfaceName).MacAddress
        
        $line = '"{0}","{1}","{2}","{3}","{4}","{5}","{6}","{7}","{8}","{9}"' -f $fullTimestamp, $computer, $user, $env:USERDOMAIN, $computerInfo.WindowsProductName, $computerInfo.OSArchitecture, $totalRAM, $interfaceName, $ipAddress, $macAddress
        $systemData += $line
    }
    
    return $systemData
} -OutputPath $systemCsvPath

# Enhanced Computer Info
Invoke-SafeCommand -Description "Detailed Computer Information" -Command {
    $computerInfo = Get-ComputerInfo
    $output = @()
    $output += "=== COMPUTER INFORMATION - $fullTimestamp ==="
    $output += "Computer Name: $($computerInfo.CsName)"
    $output += "Domain: $($computerInfo.CsDomain)"
    $output += "OS: $($computerInfo.WindowsProductName)"
    $output += "Version: $($computerInfo.WindowsVersion)"
    $output += "Build: $($computerInfo.WindowsBuildLabEx)"
    $output += "Architecture: $($computerInfo.OSArchitecture)"
    $output += "Install Date: $($computerInfo.WindowsInstallDateFromRegistry)"
    $output += "Last Boot: $($computerInfo.CsBootUpTime)"
    $output += "Total RAM: $([math]::Round($computerInfo.TotalPhysicalMemory / 1GB, 2)) GB"
    $output += "Available RAM: $([math]::Round($computerInfo.AvailablePhysicalMemory / 1GB, 2)) GB"
    $output += "Manufacturer: $($computerInfo.CsManufacturer)"
    $output += "Model: $($computerInfo.CsModel)"
    $output += "BIOS Version: $($computerInfo.BiosVersion)"
    $output += ""
    $output += "=== DETAILED COMPUTER INFO ==="
    $output += $computerInfo | Format-List | Out-String
    return $output
} -OutputPath $computerInfoTxtPath

# ENHANCED NETWORK DATA COLLECTION
Write-Host "`n=== NETWORK INFORMATION ===" -ForegroundColor Cyan

# Enhanced Active TCP Connections with Process Names
Invoke-SafeCommand -Description "Active TCP Connections with Process Details" -Command {
    $tcpData = @()
    $tcpData += '"Timestamp","LocalAddress","LocalPort","RemoteAddress","RemotePort","State","ProcessID","ProcessName","ProcessPath"'
    
    $tcpConnections = Get-NetTCPConnection
    foreach ($tcp in $tcpConnections) {
        try {
            $process = Get-Process -Id $tcp.OwningProcess -ErrorAction SilentlyContinue
            $processName = if ($process) { $process.Name } else { "Unknown" }
            $processPath = if ($process) { $process.Path } else { "Unknown" }
        }
        catch {
            $processName = "Unknown"
            $processPath = "Unknown"
        }
        
        $line = '"{0}","{1}","{2}","{3}","{4}","{5}","{6}","{7}","{8}"' -f $fullTimestamp, $tcp.LocalAddress, $tcp.LocalPort, $tcp.RemoteAddress, $tcp.RemotePort, $tcp.State, $tcp.OwningProcess, $processName, $processPath
        $tcpData += $line
    }
    return $tcpData
} -OutputPath $activeTcpCsvPath

# Firewall Rules Collection
Invoke-SafeCommand -Description "Windows Firewall Rules" -Command {
    $firewallRules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq $true }
    $output = @()
    $output += "=== ACTIVE FIREWALL RULES - $fullTimestamp ==="
    $output += ""
    
    foreach ($rule in $firewallRules) {
        $output += "Rule Name: $($rule.DisplayName)"
        $output += "Direction: $($rule.Direction)"
        $output += "Action: $($rule.Action)"
        $output += "Profile: $($rule.Profile)"
        $output += "Program: $($rule.Program)"
        $output += "Protocol: $($rule.Protocol)"
        $output += "Local Port: $($rule.LocalPort)"
        $output += "Remote Port: $($rule.RemotePort)"
        $output += "---"
    }
    return $output
} -OutputPath $firewallRulesPath

# ENHANCED SECURITY DATA COLLECTION
Write-Host "`n=== SECURITY INFORMATION ===" -ForegroundColor Cyan

# Enhanced Event Log Collection - Security Events
Invoke-SafeCommand -Description "Security Event Logs (Last 7 Days)" -Command {
    $startTime = (Get-Date).AddDays(-7)
    $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$startTime} -MaxEvents 1000 -ErrorAction SilentlyContinue
    
    $eventData = @()
    $eventData += "Timestamp,EventTime,EventID,Level,Provider,Message"
    
    foreach ($event in $securityEvents) {
        $message = $event.Message -replace '"', '""' -replace "`r`n", " "
        $line = "$fullTimestamp,$($event.TimeCreated),$($event.Id),$($event.LevelDisplayName),$($event.ProviderName),`"$message`""
        $eventData += $line
    }
    return $eventData
} -OutputPath $securityEventsCsvPath

# Local Users and Groups
Invoke-SafeCommand -Description "Local Users and Groups" -Command {
    $output = @()
    $output += "=== LOCAL USERS AND GROUPS - $fullTimestamp ==="
    $output += ""
    $output += "=== LOCAL USERS ==="
    $users = Get-LocalUser
    foreach ($user in $users) {
        $output += "Name: $($user.Name)"
        $output += "Enabled: $($user.Enabled)"
        $output += "Last Logon: $($user.LastLogon)"
        $output += "Password Last Set: $($user.PasswordLastSet)"
        $output += "Description: $($user.Description)"
        $output += "---"
    }
    
    $output += ""
    $output += "=== LOCAL GROUPS ==="
    $groups = Get-LocalGroup
    foreach ($group in $groups) {
        $output += "Group: $($group.Name)"
        $output += "Description: $($group.Description)"
        try {
            $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
            $output += "Members: $($members.Name -join ', ')"
        }
        catch {
            $output += "Members: Unable to retrieve"
        }
        $output += "---"
    }
    return $output
} -OutputPath $localUsersPath

# WMI Persistence Check
Invoke-SafeCommand -Description "WMI Persistence Analysis" -Command {
    $output = @()
    $output += "=== WMI PERSISTENCE ANALYSIS - $fullTimestamp ==="
    $output += ""
    
    # Check for suspicious WMI event consumers
    $output += "=== WMI EVENT CONSUMERS ==="
    $consumers = Get-WmiObject -Namespace "root\subscription" -Class "__EventConsumer" -ErrorAction SilentlyContinue
    foreach ($consumer in $consumers) {
        $output += "Name: $($consumer.Name)"
        $output += "Type: $($consumer.__CLASS)"
        if ($consumer.CommandLineTemplate) {
            $output += "Command: $($consumer.CommandLineTemplate)"
        }
        if ($consumer.ScriptText) {
            $output += "Script: $($consumer.ScriptText)"
        }
        $output += "---"
    }
    
    $output += ""
    $output += "=== WMI EVENT FILTERS ==="
    $filters = Get-WmiObject -Namespace "root\subscription" -Class "__EventFilter" -ErrorAction SilentlyContinue
    foreach ($filter in $filters) {
        $output += "Name: $($filter.Name)"
        $output += "Query: $($filter.Query)"
        $output += "---"
    }
    
    return $output
} -OutputPath $wmiPersistencePath

# ENHANCED PROCESS DATA COLLECTION
Write-Host "`n=== PROCESS INFORMATION ===" -ForegroundColor Cyan

# Enhanced Process Information with more details
Invoke-SafeCommand -Description "Running Processes with Details" -Command {
    $processes = Get-Process | Sort-Object CPU -Descending
    $processData = @()
    $processData += '"ProcessName","ProcessID","ParentProcessID","Path","CommandLine","StartTime","CPU_Time","Memory_MB","User"'
    
    foreach ($process in $processes) {
        try {
            $processInfo = Get-WmiObject -Class Win32_Process -Filter "ProcessId='$($process.Id)'" -ErrorAction SilentlyContinue
            $commandLine = if ($processInfo) { $processInfo.CommandLine } else { "N/A" }
            $parentPID = if ($processInfo) { $processInfo.ParentProcessId } else { "N/A" }
            $startTime = if ($process.StartTime) { $process.StartTime.ToString() } else { "N/A" }
            $cpuTime = if ($process.CPU) { [math]::Round($process.CPU, 2) } else { 0 }
            $memory = [math]::Round($process.WorkingSet / 1MB, 2)
            $path = if ($process.Path) { $process.Path } else { "N/A" }
            
            # Try to get process owner
            $owner = "N/A"
            try {
                $ownerInfo = $processInfo.GetOwner()
                if ($ownerInfo.Domain -and $ownerInfo.User) {
                    $owner = "$($ownerInfo.Domain)\$($ownerInfo.User)"
                }
            }
            catch { }
            
            $commandLine = $commandLine -replace '"', '""'
            $line = '"{0}","{1}","{2}","{3}","{4}","{5}","{6}","{7}","{8}"' -f $process.Name, $process.Id, $parentPID, $path, $commandLine, $startTime, $cpuTime, $memory, $owner
            $processData += $line
        }
        catch {
            # If we can't get detailed info, add basic info
            $line = '"{0}","{1}","N/A","N/A","N/A","N/A","0","0","N/A"' -f $process.Name, $process.Id
            $processData += $line
        }
    }
    return $processData
} -OutputPath $processesTxtPath

# Services with more details
Invoke-SafeCommand -Description "System Services" -Command {
    $services = Get-Service | Sort-Object Status, Name
    $serviceData = @()
    $serviceData += '"ServiceName","DisplayName","Status","StartType","PathName","Description","LogOnAs"'
    
    foreach ($service in $services) {
        try {
            $serviceInfo = Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue
            $startType = if ($serviceInfo) { $serviceInfo.StartMode } else { "Unknown" }
            $pathName = if ($serviceInfo) { $serviceInfo.PathName } else { "Unknown" }
            $description = if ($serviceInfo) { $serviceInfo.Description } else { "" }
            $logOnAs = if ($serviceInfo) { $serviceInfo.StartName } else { "Unknown" }
            
            $pathName = $pathName -replace '"', '""'
            $description = $description -replace '"', '""'
            
            $line = '"{0}","{1}","{2}","{3}","{4}","{5}","{6}"' -f $service.Name, $service.DisplayName, $service.Status, $startType, $pathName, $description, $logOnAs
            $serviceData += $line
        }
        catch {
            $line = '"{0}","{1}","{2}","Unknown","Unknown","","Unknown"' -f $service.Name, $service.DisplayName, $service.Status
            $serviceData += $line
        }
    }
    return $serviceData
} -OutputPath $servicesTxtPath

# Continue with existing collections (DNS Cache, Network Data, etc.)
# ... (previous code for DNS, Network, HotFix, Recent Files, etc.)

# FINAL SUMMARY REPORT
$summaryPath = Join-Path -Path $folderPath -ChildPath "IR_Collection_Summary.txt"
$summary = @()
$summary += "=== INCIDENT RESPONSE COLLECTION SUMMARY ==="
$summary += "Collection Time: $fullTimestamp"
$summary += "Computer: $computer"
$summary += "User: $user"
$summary += "Domain: $env:USERDOMAIN"
$summary += ""
$summary += "=== FILES COLLECTED ==="
Get-ChildItem -Path $folderPath -Recurse -File | ForEach-Object {
    $summary += "$($_.FullName) - $($_.Length) bytes"
}

$summary | Out-File -FilePath $summaryPath -Encoding utf8

Write-Host "`n=== COLLECTION COMPLETE ===" -ForegroundColor Green
Write-Host "All data collected in: $folderPath" -ForegroundColor Cyan
Write-Host "Summary report: $summaryPath" -ForegroundColor Cyan
Write-Host "`nUNLIMITED POWAAAAAAA - Papa Palp" -ForegroundColor Yellow

# Optional: Create a ZIP archive of all collected data
$zipPath = "$folderPath.zip"
try {
    Compress-Archive -Path $folderPath -DestinationPath $zipPath -CompressionLevel Optimal
    Write-Host "Archive created: $zipPath" -ForegroundColor Green
}
catch {
    Write-Warning "Could not create ZIP archive: $($_.Exception.Message)"
}
# RAM DUMP purposely kept out but can be useful if need be
# procdump -ma -x C:\path\to\dumpdirectory
