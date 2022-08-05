
param (
    
    [Parameter(Mandatory=$false,HelpMessage="Please enter your task path")]
	[String]$TaskPath="CyberArkAutomation",
    [Parameter(Mandatory=$false,HelpMessage="Please enter your username")]
	[String]$User="NT AUTHORITY\SYSTEM",
    [Parameter(Mandatory=$false,HelpMessage="Please specify if this is for pilot")]
	[switch]$Pilot
)

$Environment = "CyberArkAutomation"
$PilotArgument = ""
if($Pilot){
    $Environment = "CyberArkAutomationPilot"
    $TaskPath = $Environment
    $PilotArgument = " -Pilot"
}

$DestinationFolder="c:\$Environment"

$continue = Read-Host -Prompt "The automation environment will be deployed to $DestinationFolder. Is this ok? (y/n)"
if($continue.ToUpper() -ne "Y"){Return}

$loadTasks = Read-Host -Prompt "Load or reload tasks? Is thi ok? (y/n)"
$continueLoadTasks = $loadTasks.ToUpper() -eq "Y"

try {
    IF(-not (Test-Path $DestinationFolder)){New-Item $DestinationFolder -ItemType "directory"}
    [System.Environment]::SetEnvironmentVariable("$Environment", $DestinationFolder, [System.EnvironmentVariableTarget]::Machine)
    [System.Environment]::SetEnvironmentVariable("$Environment", $DestinationFolder, [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("$Environment", $DestinationFolder, [System.EnvironmentVariableTarget]::User)
    
}catch{
    Throw $Error[0]
    Write-Verbose "Could not setup environment using destination folder '$DestinationFolder'"
    return
}



# $ScheduledTasks = @(
#     [PSCustomObject]@{TaskName = "01 Generate Server Reports"},
#     [PSCustomObject]@{TaskName = "02 Generate Pending Accounts Report"},
#     [PSCustomObject]@{TaskName = "03 Get Account Data"},
#     [PSCustomObject]@{TaskName = "04 Update Unix Server Lists for Account Discovery Scanning"},
#     [PSCustomObject]@{TaskName = "05 Validate CSV Files"},
#     [PSCustomObject]@{TaskName = "06 Generate Onboarding Files"},
    
#     [PSCustomObject]@{TaskName = "07 Move Accounts"},
#     [PSCustomObject]@{TaskName = "08 Delete Pending Accounts"},
#     [PSCustomObject]@{TaskName = "09 Delete Accounts"}
    

# )

if($Pilot){
    $PATH_SCRIPTS_FOLDER                                = "$env:CyberArkAutomationPilot\SCRIPTS"
    $PATH_SCRIPTS_REPO_FOLDER                           = "$env:CyberArkAutomationPilot\SCRIPTS\REPO"
    $PATH_SCRIPTS_REPO_CYBERARK_FOLDER                  = "$env:CyberArkAutomationPilot\SCRIPTS\REPO\CYBERARK"
    $PATH_SCRIPTS_REPO_CYBERARK_ST_FOLDER               = "$env:CyberArkAutomationPilot\SCRIPTS\REPO\CYBERARK\SCHEDULEDTASKS"
    $PATH_SCRIPTS_REPO_CYBERARK_ST_SCRIPTS_FOLDER       = "$env:CyberArkAutomationPilot\SCRIPTS\REPO\CYBERARK\SCHEDULEDTASKS\SCRIPTS"
    $PATH_SCRIPTS_LOG_FOLDER                            = "$env:CyberArkAutomationPilot\SCRIPTS\LOGS"
    $PATH_SCRIPTS_AUTOMATION_FOLDER                     = "$env:CyberArkAutomationPilot\SCRIPTS\AUTOMATION"
    $PATH_SCRIPTS_AUTOMATION_REGEX_FOLDER               = "$env:CyberArkAutomationPilot\SCRIPTS\AUTOMATION\REGEX"
    $PATH_DATA_FOLDER                                   = "$env:CyberArkAutomationPilot\DATA"
    $PATH_DATA_FROMCYBERARK_FOLDER                      = "$env:CyberArkAutomationPilot\DATA\FROMCYBERARK"
    $PATH_DATA_TOCYBERARK_FOLDER                        = "$env:CyberArkAutomationPilot\DATA\TOCYBERARK"
    $PATH_DATA_ONBOARD_FOLDER                           = "$env:CyberArkAutomationPilot\DATA\ONBOARDACCOUNTS"
    $PATH_DATA_OFFBOARD_FOLDER                          = "$env:CyberArkAutomationPilot\DATA\OFFBOARDACCOUNTS"
    $PATH_DATA_ONBOARD_ARCHIVE_FOLDER                   = "$env:CyberArkAutomationPilot\DATA\ONBOARDACCOUNTS\ARCHIVE"
}else{
    $PATH_SCRIPTS_FOLDER                                = "$env:CyberArkAutomation\SCRIPTS"
    $PATH_SCRIPTS_REPO_FOLDER                           = "$env:CyberArkAutomation\SCRIPTS\REPO"
    $PATH_SCRIPTS_REPO_CYBERARK_FOLDER                  = "$env:CyberArkAutomation\SCRIPTS\REPO\CYBERARK"
    $PATH_SCRIPTS_REPO_CYBERARK_ST_FOLDER               = "$env:CyberArkAutomation\SCRIPTS\REPO\CYBERARK\SCHEDULEDTASKS"
    $PATH_SCRIPTS_REPO_CYBERARK_ST_SCRIPTS_FOLDER       = "$env:CyberArkAutomation\SCRIPTS\REPO\CYBERARK\SCHEDULEDTASKS\SCRIPTS"
    $PATH_SCRIPTS_LOG_FOLDER                            = "$env:CyberArkAutomation\SCRIPTS\LOGS"
    $PATH_SCRIPTS_AUTOMATION_FOLDER                     = "$env:CyberArkAutomation\SCRIPTS\AUTOMATION"
    $PATH_SCRIPTS_AUTOMATION_REGEX_FOLDER               = "$env:CyberArkAutomation\SCRIPTS\AUTOMATION\REGEX"
    $PATH_DATA_FOLDER                                   = "$env:CyberArkAutomation\DATA"
    $PATH_DATA_FROMCYBERARK_FOLDER                      = "$env:CyberArkAutomation\DATA\FROMCYBERARK"
    $PATH_DATA_TOCYBERARK_FOLDER                        = "$env:CyberArkAutomation\DATA\TOCYBERARK"
    $PATH_DATA_ONBOARD_FOLDER                           = "$env:CyberArkAutomation\DATA\ONBOARDACCOUNTS"
    $PATH_DATA_OFFBOARD_FOLDER                          = "$env:CyberArkAutomation\DATA\OFFBOARDACCOUNTS"
    $PATH_DATA_ONBOARD_ARCHIVE_FOLDER                   = "$env:CyberArkAutomation\DATA\ONBOARDACCOUNTS\ARCHIVE"
}



#Create Folders
IF(-not (Test-Path $PATH_SCRIPTS_FOLDER)){New-Item $PATH_SCRIPTS_FOLDER -ItemType "directory"}
IF(-not (Test-Path $PATH_SCRIPTS_REPO_FOLDER)){New-Item $PATH_SCRIPTS_REPO_FOLDER -ItemType "directory"}
IF(-not (Test-Path $PATH_SCRIPTS_REPO_CYBERARK_FOLDER)){New-Item $PATH_SCRIPTS_REPO_CYBERARK_FOLDER -ItemType "directory"}
IF(-not (Test-Path $PATH_SCRIPTS_LOG_FOLDER)){New-Item $PATH_SCRIPTS_LOG_FOLDER -ItemType "directory"}
IF(-not (Test-Path $PATH_SCRIPTS_AUTOMATION_FOLDER)){New-Item $PATH_SCRIPTS_AUTOMATION_FOLDER -ItemType "directory"}
IF(-not (Test-Path $PATH_SCRIPTS_AUTOMATION_REGEX_FOLDER)){New-Item $PATH_SCRIPTS_AUTOMATION_REGEX_FOLDER -ItemType "directory"}
IF(-not (Test-Path $PATH_DATA_FOLDER)){New-Item $PATH_DATA_FOLDER -ItemType "directory"}
IF(-not (Test-Path $PATH_DATA_FROMCYBERARK_FOLDER)){New-Item $PATH_DATA_FROMCYBERARK_FOLDER -ItemType "directory"}
IF(-not (Test-Path $PATH_DATA_TOCYBERARK_FOLDER)){New-Item $PATH_DATA_TOCYBERARK_FOLDER -ItemType "directory"}
IF(-not (Test-Path $PATH_DATA_ONBOARD_FOLDER)){New-Item $PATH_DATA_ONBOARD_FOLDER -ItemType "directory"}
IF(-not (Test-Path $PATH_DATA_OFFBOARD_FOLDER)){New-Item $PATH_DATA_OFFBOARD_FOLDER -ItemType "directory"}
IF(-not (Test-Path $PATH_DATA_ONBOARD_ARCHIVE_FOLDER)){New-Item $PATH_DATA_ONBOARD_ARCHIVE_FOLDER -ItemType "directory"}




IF((Test-Path $PATH_SCRIPTS_REPO_CYBERARK_ST_SCRIPTS_FOLDER)){
    Remove-Item $PATH_SCRIPTS_REPO_CYBERARK_ST_SCRIPTS_FOLDER -Force -Recurse
}
IF((Test-Path $PATH_SCRIPTS_REPO_CYBERARK_ST_FOLDER)){
    Remove-Item $PATH_SCRIPTS_REPO_CYBERARK_ST_FOLDER -Force -Recurse
}

# New-Item $PATH_SCRIPTS_REPO_CYBERARK_ST_FOLDER
# New-Item $PATH_SCRIPTS_REPO_CYBERARK_ST_SCRIPTS_FOLDER

#Copy script files
$SourceFolder = (Get-Location).Path
Copy-Item -Path ("$SourceFolder\*") -Destination $PATH_SCRIPTS_REPO_CYBERARK_FOLDER -Recurse -Force

#Update Tasks
if($continueLoadTasks){

    Write-Verbose "Attempt to remove task (if exist)"
    try {
        $Tasks = Get-ScheduledTask -TaskPath "\$TaskPath\" -ErrorAction SilentlyContinue
        if(($Tasks | measure).Count -gt 0){
            $Tasks | Foreach-Object {
                Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
        
    } catch {
        Write-Verbose "Could not register all tasks!"
    }
    
    
    
    
    #$ScheduledTasks | Foreach-Object {
    Get-ChildItem -Path .\ScheduledTasks\*.xml | Foreach-Object {
        
        $task = [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
        $path = ("$PATH_SCRIPTS_REPO_CYBERARK_ST_FOLDER\{0}.xml" -f $task)
        if($path -ne $null -and (Test-Path -Path $path)){
            Write-Verbose "Update environment variable in task action for file '$path'"
        
            $replaceContent = Get-Content $path
            $replaceContent = $replaceContent -replace "_environment_",$DestinationFolder
            $replaceContent = $replaceContent -replace "_taskpath_",$TaskPath
            $replaceContent = $replaceContent -replace "_pilotarg_",$PilotArgument
            $replaceContent | Out-File $path
            
            Write-Verbose "Register task '$task' with file '$path'"
            try {
            
                Register-ScheduledTask -xml (Get-Content $path | Out-String) -TaskName $task -TaskPath "\$TaskPath\" -User $User
            }catch{
    
            }
        }else{
            Write-Verbose "The Schedule Task XML file '$path' does not exist!"
        }
        
    
    
    }
    
}



