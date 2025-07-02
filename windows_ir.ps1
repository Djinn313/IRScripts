# Set path to Desktop and IR results folder
$desktopPath = [Environment]::GetFolderPath("Desktop")
$folderPath = Join-Path -Path $desktopPath -ChildPath "IR results"

# Create "IR results" folder if it doesn't exist
if (!(Test-Path -Path $folderPath)) {
    New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# File Paths
$systemCsvPath = Join-Path -Path $folderPath -ChildPath "SystemData.csv"
$activeTcpCsvPath = Join-Path -Path $folderPath -ChildPath "Active TCP.csv"
$networkTxtPath = Join-Path -Path $folderPath -ChildPath "Network Data.txt"
$eventsCsvPath = Join-Path -Path $folderPath -ChildPath "EventLogs.csv"
$computerInfoTxtPath = Join-Path -Path $folderPath -ChildPath "ComputerInfo.txt"
$processesTxtPath = Join-Path -Path $folderPath -ChildPath "Processes.txt"
$servicesTxtPath = Join-Path -Path $folderPath -ChildPath "Services.txt"
$networkNeighborsTxtPath = Join-Path -Path $folderPath -ChildPath "Network Neighbors.txt"
$dnsCacheTxtPath = Join-Path -Path $folderPath -ChildPath "DNSCache.txt"
$hotfixCsvPath = Join-Path -Path $folderPath -ChildPath "HotFixes.csv"
$recentModifiedFilesPath = Join-Path -Path $folderPath -ChildPath "Recently Modified System Files.txt"
$scheduledTasksTxtPath = Join-Path -Path $folderPath -ChildPath "ScheduledTasks.txt"
$recentInstalledProgramsPath = Join-Path -Path $folderPath -ChildPath "Recently Installed Programs.txt"
$startupProgramsTxtPath = Join-Path -Path $folderPath -ChildPath "StartupPrograms.txt"
$groupPolicySettingsXmlPath = Join-Path -Path $folderPath -ChildPath "GroupPolicySettings.xml"

# Used Values
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$computer = $env:COMPUTERNAME
$user = $env:USERNAME

# Do the thing
Write-Host "DO THE THING!" -ForegroundColor Green

# System Data (CSV)
if (!(Test-Path -Path $systemCsvPath)) {
    '"Timestamp","ComputerName","Username","InterfaceName","IPv4Address","MACAddress"' | Out-File -FilePath $systemCsvPath -Encoding utf8
}

$systemLines = @()
$adapters = Get-NetIPConfiguration | Where-Object { $_.IPv4Address }

foreach ($adapter in $adapters) {
    $interfaceName = $adapter.InterfaceAlias
    $ipAddress     = $adapter.IPv4Address.IPAddress
    $macAddress    = (Get-NetAdapter -InterfaceAlias $interfaceName).MacAddress

    $line = '"{0}","{1}","{2}","{3}","{4}","{5}"' -f $timestamp, $computer, $user, $interfaceName, $ipAddress, $macAddress
    $systemLines += $line
}

$systemLines | Out-File -FilePath $systemCsvPath -Append -Encoding utf8

# Computer Info (TXT)
$computerInfo = Get-ComputerInfo
$computerInfoText = @()
$computerInfoText += "Computer Info - $timestamp"
$computerInfoText += "=============================="
$computerInfoText += $computerInfo
$computerInfoText | Out-File -FilePath $computerInfoTxtPath -Encoding utf8

# DNS Client Cache (TXT)
$dnsCache = Get-DnsClientCache
$dnsCacheText = @()
$dnsCacheText += "DNS Cache - $timestamp"
$dnsCacheText += "=============================="
$dnsCacheText += $dnsCache
$dnsCacheText | Out-File -FilePath $dnsCacheTxtPath -Encoding utf8

# Get HotFix (CSV)
if (!(Test-Path -Path $hotfixCsvPath)) {
    '"Description","HotFixID","InstalledBy","InstalledOn"' | Out-File -FilePath $hotfixCsvPath -Encoding utf8
}

$hotfixes = Get-HotFix
$hotfixCsvData = @()

foreach ($hotfix in $hotfixes) {
    $line = '"{0}","{1}","{2}","{3}"' -f $hotfix.Description, $hotfix.HotFixID, $hotfix.InstalledBy, $hotfix.InstalledOn
    $hotfixCsvData += $line
}

$hotfixCsvData | Out-File -FilePath $hotfixCsvPath -Append -Encoding utf8

# Network Data (TXT)
$tcpConnections = (Get-NetTCPConnection | Measure-Object).Count
$udpEndpoints = (Get-NetUDPEndpoint | Measure-Object).Count
$listenConnections = (Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } | Measure-Object).Count
$netConfigs = Get-NetIPConfiguration

$netText = @()
$netText += "Network Data Collection - $timestamp"
$netText += "Computer: $computer"
$netText += "User: $user"
$netText += ""

foreach ($config in $netConfigs) {
    $interfaceAlias = $config.InterfaceAlias
    $ipv4 = $config.IPv4Address.IPAddress
    $dns = $config.DNSServer.ServerAddresses -join ', '

    $netText += "Interface: $interfaceAlias"
    $netText += "IPv4 Address: $ipv4"
    $netText += "DNS Servers: $dns"
    $netText += "Total TCP Connections: $tcpConnections"
    $netText += "UDP Endpoints: $udpEndpoints"
    $netText += "Listening TCP Connections: $listenConnections"
    $netText += "--------------------------------------------------"
    $netText += ""
}

$netText | Out-File -FilePath $networkTxtPath -Encoding utf8

# Active TCP Connections (CSV, might be better in HTML though)
if (!(Test-Path -Path $activeTcpCsvPath)) {
    '"Timestamp","LocalAddress","LocalPort","RemoteAddress","RemotePort","State","OwningProcess"' | Out-File -FilePath $activeTcpCsvPath -Encoding utf8
}

$activeTcpConnections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
$tcpLines = @()

foreach ($tcp in $activeTcpConnections) {
    $line = '"{0}","{1}","{2}","{3}","{4}","{5}","{6}"' -f $timestamp, $tcp.LocalAddress, $tcp.LocalPort, $tcp.RemoteAddress, $tcp.RemotePort, $tcp.State, $tcp.OwningProcess
    $tcpLines += $line
}

$tcpLines | Out-File -FilePath $activeTcpCsvPath -Append -Encoding utf8

# System Event Logs Last 24 hours (can be adjusted as needed)
try {
    $startTime = (Get-Date).AddDays(-1)  # Last 24 hours
    $eventLogs = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$startTime} -ErrorAction Stop |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName
    $eventLogCsvData = @()
    $eventLogCsvData += "Timestamp,EventTime,EventID,Level,Provider"

    foreach ($event in $eventLogs) {
        $line = "$timestamp,$($event.TimeCreated),$($event.Id),$($event.LevelDisplayName),$($event.ProviderName)"
        $eventLogCsvData += $line
    }

    $eventLogCsvData | Out-File -FilePath $eventsCsvPath -Encoding utf8
} catch {
    Write-Warning "No system events found or unable to retrieve events. Error: $($_.Exception.Message)"
}

# Processes (TXT)
$processes = Get-Process
$processesText = @()
$processesText += "Processes - $timestamp"
$processesText += "=============================="
foreach ($process in $processes) {
    $processesText += "Name: $($process.Name) | ID: $($process.Id) | CPU: $($process.CPU)"
}
$processesText | Out-File -FilePath $processesTxtPath -Encoding utf8

# Services (TXT)
$services = Get-Service
$servicesText = @()
$servicesText += "Services - $timestamp"
$servicesText += "=============================="
foreach ($service in $services) {
    $servicesText += "Name: $($service.Name) | Status: $($service.Status)"
}
$servicesText | Out-File -FilePath $servicesTxtPath -Encoding utf8

# Net Neighbor (TXT)
$netNeighbors = Get-NetNeighbor
$networkNeighborsText = @()
$networkNeighborsText += "Network Neighbors - $timestamp"
$networkNeighborsText += "=============================="
foreach ($neighbor in $netNeighbors) {
    $networkNeighborsText += "IPAddress: $($neighbor.IPAddress) | LinkLayerAddress: $($neighbor.LinkLayerAddress) | State: $($neighbor.State)"
}
$networkNeighborsText | Out-File -FilePath $networkNeighborsTxtPath -Encoding utf8

# Recently Modified System Files (Last 1 Day adjust as needed)
$recentFiles = Get-ChildItem -Path "C:\Windows\System32" -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) } |
    Select-Object FullName, LastWriteTime

$recentFileText = @()
$recentFileText += "Recently Modified System Files - $timestamp"
$recentFileText += "=============================="
foreach ($file in $recentFiles) {
    $recentFileText += "Path: $($file.FullName) | Modified: $($file.LastWriteTime)"
}

if ($recentModifiedFilesPath) {
    $recentFileText | Out-File -FilePath $recentModifiedFilesPath -Encoding utf8
} else {
    Write-Warning "recentModifiedFilesPath is null. Skipping output."
}

# Recently Installed Programs Last 30 Days
$installedPrograms = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
$installedPrograms += Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue

$recentInstalledPrograms = $installedPrograms | Where-Object { 
    $installDate = $_.InstallDate
    if ($installDate) {
        $date = [datetime]::ParseExact($installDate, 'yyyyMMdd', $null)
        $date -gt (Get-Date).AddDays(-30)
    }
} | Select-Object DisplayName, InstallDate | Sort-Object InstallDate -Descending

$recentInstalledProgramsText = @()
$recentInstalledProgramsText += "Recently Installed Programs - $timestamp"
$recentInstalledProgramsText += "=============================="

foreach ($program in $recentInstalledPrograms) {
    $recentInstalledProgramsText += "Program: $($program.DisplayName) | Installed On: $($program.InstallDate)"
}

$recentInstalledProgramsText | Out-File -FilePath $recentInstalledProgramsPath -Encoding utf8

# Startup Programs Report (HTML)
$startupHtmlReportPath = Join-Path -Path $folderPath -ChildPath "Startup_Programs_Report.html"

# Helper function to format entries
function Format-StartupEntry {
    param (
        [string]$Source,
        [string]$Name,
        [string]$Command
    )
    [PSCustomObject]@{
        Source  = $Source
        Name    = $Name
        Command = $Command
    }
}

# Registry startup items
$startupItems = @()
$registryPaths = @{
    "Registry (Current User)" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    "Registry (All Users)"    = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    "Registry (WOW6432Node)"  = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
}

foreach ($source in $registryPaths.Keys) {
    try {
        $entries = Get-ItemProperty -Path $registryPaths[$source] -ErrorAction Stop
        foreach ($name in $entries.PSObject.Properties.Name) {
            $command = $entries.$name
            $startupItems += Format-StartupEntry -Source $source -Name $name -Command $command
        }
    } catch {
        # Skip inaccessible keys
    }
}

# Startup folder shortcuts
$startupFolders = @{
    "Startup Folder (Current User)" = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    "Startup Folder (All Users)"    = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
}

foreach ($source in $startupFolders.Keys) {
    if (Test-Path $startupFolders[$source]) {
        $files = Get-ChildItem -Path $startupFolders[$source] -Filter *.lnk -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            $startupItems += Format-StartupEntry -Source $source -Name $file.Name -Command $file.FullName
        }
    }
}

# Scheduled tasks that trigger at log in
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.Triggers | Where-Object { $_.TriggerType -eq 'Logon' }
}
foreach ($task in $tasks) {
    foreach ($action in $task.Actions) {
        $command = "$($action.Execute) $($action.Arguments)".Trim()
        $startupItems += Format-StartupEntry -Source "Scheduled Task" -Name $task.TaskName -Command $command
    }
}

$startupItems | Sort-Object Source, Name |
    ConvertTo-Html -Title "Startup Programs Report" -PreContent "<h1>Startup Programs Report</h1><p>Generated on $(Get-Date)</p>" |
    Out-File -Encoding UTF8 $startupHtmlReportPath

# Group Policy Settings (XML)
if ($env:USERDOMAIN) {
    try {
        $gpoSettings = Get-GPOReport -All -ReportType Xml
        $gpoSettings | Out-File -FilePath $groupPolicySettingsXmlPath -Encoding utf8
    } catch {
        Write-Warning "Unable to retrieve Group Policy settings: $($_.Exception.Message)"
    }
} else {
    Write-Warning "Machine is not part of an Active Directory domain. Skipping Group Policy retrieval."
}

Write-Host "Incident Response Data Collection Complete!" -ForegroundColor Green 
Write-Host "UNLIMTED POWAAAAAAA - Papa Palp" -ForegroundColor Yellow
#Start-Process https://www.youtube.com/shorts/Cm7lXXM70eQ  

# RAM DUMP purposely kept out but can be useful if need be
# procdump -ma -x C:\path\to\dumpdirectory
