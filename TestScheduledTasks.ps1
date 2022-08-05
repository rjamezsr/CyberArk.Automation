 [cmdletbinding()]

 Param([switch]$Pilot)

 $PathSuffix = ""
function ValidTask {
    param($taskName)
    try {
        (Get-ScheduledTask -TaskPath "\CyberArkAutomation$PathSuffix\" | Where TaskName -eq $taskName) -ne $null
    }catch{
        $false
    }
}
function TaskIsDisabled {
    param($taskName)

    try {
        (Get-ScheduledTask -TaskPath "\CyberArkAutomation$PathSuffix\" | Where TaskName -eq $taskName).State -eq "Disabled"             
    }catch{
        $false
    }


}
function TaskIsReady {
    param($taskName)
    try {
        (Get-ScheduledTask -TaskPath "\CyberArkAutomation$PathSuffix\" | Where TaskName -eq $taskName).State -eq "Ready"
    }catch{
        $false
    }
    
}
function TaskIsRunning {
    param($taskName)

    try {
        (Get-ScheduledTask -TaskPath "\CyberArkAutomation$PathSuffix\" | Where TaskName -eq $taskName).State -eq "Running"
    }catch{
        $false
    }
}
function EnableTask {
    param($taskName)
    if(TaskIsDisabled -taskName $taskName){
        Write-Verbose "Enabling tasks '$_'"
        try {
            Enable-ScheduledTask -TaskName "\CyberArkAutomation$PathSuffix\$taskName"
        }catch{
            $false
        }
    }
    TaskIsReady -taskName $taskName
}
function StartTask {
    param($taskName,$MaxAttempts,$WaitSecords)
    Write-Verbose "Starting task '$taskName'..."
    try {
        Start-ScheduledTask -TaskName "\CyberArkAutomation$PathSuffix\$taskName"
        Start-Sleep -Seconds $WaitSecords
    }catch{
        $false
    }
    
    $attemts = 0
    while ((TaskIsReady -taskName $taskName) -eq $false -and $attemts -lt $MaxAttempts){
        Write-Verbose "Task running..."
        Start-Sleep -Seconds $WaitSecords
        $attempts = $attempts + 1
    }
    $true
}

function DisableTask {
    param($taskName)
    try {
        Write-Verbose "Disabling tasks '$taskName'"
        Disable-ScheduledTask -TaskName "\CyberArkAutomation$PathSuffix\$taskName"
    }catch{
        $false
    }
    
    TaskIsDisabled -taskName $taskName
}

if($Pilot){
    $PathSuffix = "Pilot"
}

$Tasks = [System.Collections.ArrayList]@()
[void]$Tasks.Add("01 Generate Server Reports")
[void]$Tasks.Add("02 Generate Pending Accounts Report")
[void]$Tasks.Add("03 Get Account Data")
[void]$Tasks.Add("04 Update Unix Server Lists for Account Discovery Scanning")
[void]$Tasks.Add("05 Validate CSV Files")
[void]$Tasks.Add("06 Generate Onboarding Files")
[void]$Tasks.Add("07 Onboard New Accounts")
[void]$Tasks.Add("08 Move Accounts")
[void]$Tasks.Add("09 Delete Pending Accounts")
[void]$Tasks.Add("10 Delete Accounts")


$MaxAttempts = 100
$WaitSecords = 3

$Tasks | ForEach-Object {
    $continue = $true
    if(ValidTask -taskName $_){
        if(TaskIsDisabled -taskName $_){
            EnableTask -taskName $_
        }
        if(TaskIsReady -taskName $_){
            if(StartTask -taskName $_ -MaxAttempts $MaxAttempts -WaitSecords $WaitSecords){
                Write-Verbose "Task '$_' is complete"
                DisableTask -taskName $_
            }
        }
    }
    if($continue){

    }else{
        Write-Verbose "Abort"
    }
}



