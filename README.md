# ProcessHunter
Process Investigation Script
This PowerShell script is designed for analyzing a running process on a Windows system. The script performs several tasks, including:

Retrieving and displaying process details such as the command line, file path, and hash (SHA256).
Checking the process file hash against VirusTotal to identify if the file is flagged as malicious.
Monitoring the process’s network connections and checking destination IP addresses against AbuseIPDB.
Listing DLLs loaded by the process.
Identifying the parent process and whether it interacted with reg.exe.
Displaying child processes spawned by the selected process.
Prerequisites
Before using this script, ensure the following:

A VirusTotal API key is required to check process file hashes.
An AbuseIPDB API key is required to check IP addresses associated with network connections.
The script requires administrative privileges on the system to retrieve process details using WMI.
Script Breakdown
Variables
$vtAPIKey: Your VirusTotal API key.
$abuseIPDBKey: Your AbuseIPDB API key.
Input
Read-Host "Enter the process name": The user is prompted to enter the name of the process to analyze.
Process Details
The script fetches process details using WMI with Get-WmiObject. It retrieves:
Command line used to launch the process.
Executable file path.
SHA256 hash of the executable file.
VirusTotal Integration
The function CheckVirusTotalHash:

Sends the process hash to VirusTotal for verification.
Retrieves and displays the number of antivirus engines that flagged the file as malicious.
Network Connections and AbuseIPDB Integration
The script queries network connections associated with the process using WMI.
For each connection, it checks the destination IP address using the AbuseIPDB API to assess if the IP is malicious, based on the abuse confidence score.
DLLs Loaded by the Process
The script lists all DLL modules loaded by the process using Get-WmiObject Win32_ProcessModule.
Parent and Child Processes
The script checks the parent process and whether it interacted with reg.exe (which can be indicative of malicious registry modifications).
It also lists any child processes spawned by the target process.
Setup Instructions
Install PowerShell:

This script is designed to run on Windows systems with PowerShell 5.1 or later.
API Keys:

You must acquire valid API keys from VirusTotal and AbuseIPDB.
Replace the placeholder strings "YOUR_VT_API" and "YOUR_ABUSEIP_IP" with your actual API keys in the script.
Running the Script:

Open PowerShell as an administrator.
Execute the script by running it in the PowerShell terminal.
Enter the name of the process you want to analyze when prompted.
Example Usage
Run the script and enter the process name when prompted, for example: powershell.exe.
The script will output the following details:
Command line used to start the process.
File path and SHA256 hash of the executable.
VirusTotal results (if any).
Any active network connections and their AbuseIPDB scores.
List of DLLs loaded by the process.
Information about the parent process and whether it used reg.exe.
Any child processes spawned by the target process.
Notes
Ensure that you have internet access to connect to the VirusTotal and AbuseIPDB APIs.
This script is primarily for investigative and forensic purposes on live systems. Use caution while running it on sensitive systems.

![image](https://github.com/user-attachments/assets/3a3a3061-0dee-41eb-b508-562cdad5ce2a)

![image](https://github.com/user-attachments/assets/fb31f4a9-f67a-45e2-8a80-fef675d27c61)


