
$vtAPIKey = "YOUR_VT_API"
$abuseIPDBKey = "YOUR_ABUSIP_IP"


$processName = Read-Host "Enter the process name"


$process = Get-WmiObject Win32_Process | Where-Object { $_.Name -eq $processName }

if ($process -eq $null) {
    Write-Host "Process not found!"
    exit
}


$commandLine = $process.CommandLine
$filePath = $process.ExecutablePath

Write-Host "Process Command Line: $commandLine"
Write-Host "Process File Path: $filePath"


$hash = Get-FileHash -Path $filePath -Algorithm SHA256
$processHash = $hash.Hash
Write-Host "Process Hash: $processHash"


function CheckVirusTotalHash {
    param ($hash)

    $url = "https://www.virustotal.com/vtapi/v2/file/report"
    $params = @{
        apikey = $vtAPIKey
        resource = $hash
    }

    $response = Invoke-RestMethod -Uri $url -Method Get -Body $params
    if ($response.response_code -eq 1) {
        Write-Host "VirusTotal Result: $($response.positives)/$($response.total) vendors marked as malicious."
    } else {
        Write-Host "VirusTotal Result: No results found for this hash."
    }
}

CheckVirusTotalHash $processHash


$networkConnections = Get-WmiObject -Query "SELECT * FROM Win32_PerfFormattedData_Tcpip_NetworkInterface"
if ($networkConnections) {
    foreach ($connection in $networkConnections) {
        $destinationIP = $connection.CurrentConnections
        Write-Host "Process is connecting to IP: $destinationIP"

        
        function CheckAbuseIPDB {
            param ($ip)

            $url = "https://api.abuseipdb.com/api/v2/check"
            $headers = @{
                Key = $abuseIPDBKey
                Accept = "application/json"
            }
            $params = @{
                ipAddress = $ip
            }

            $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers -Body $params
            if ($response) {
                Write-Host "AbuseIPDB Result: $($response.data.abuseConfidenceScore)% confidence score."
            } else {
                Write-Host "AbuseIPDB Result: No results found for this IP."
            }
        }

        CheckAbuseIPDB $destinationIP
    }
}



$dlls = Get-WmiObject Win32_ProcessModule | Where-Object { $_.ProcessId -eq $process.ProcessId }
Write-Host "DLLs loaded by the process:"
foreach ($dll in $dlls) {
    Write-Host $dll.ModuleName
}


$parentProcess = Get-WmiObject Win32_Process | Where-Object { $_.ProcessId -eq $process.ParentProcessId }
if ($parentProcess.Name -eq "reg.exe") {
    Write-Host "Process interacted with reg.exe"
} else {
    Write-Host "Process did not interact with reg.exe"
}


$parentProcessPath = $parentProcess.ExecutablePath
Write-Host "Parent Process: $($parentProcess.Name)"
Write-Host "Parent Process Path: $parentProcessPath"


$childProcesses = Get-WmiObject Win32_Process | Where-Object { $_.ParentProcessId -eq $process.ProcessId }
if ($childProcesses) {
    Write-Host "Child Processes:"
    foreach ($child in $childProcesses) {
        Write-Host $child.Name
    }
} else {
    Write-Host "No child processes found."
}
