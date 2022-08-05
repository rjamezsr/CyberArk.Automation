param (
    [Parameter(Mandatory=$false,HelpMessage="Please specify if this is for pilot")]
	[switch]$Pilot
)

$scriptPath = "$env:CyberArkAutomation\scripts"
$dataPath = "$env:CyberArkAutomation\data"
if($Pilot){
    $scriptPath = "$env:CyberArkAutomationPilot\scripts"
    $dataPath = "$env:CyberArkAutomationPilot\data"
}

Set-Location "$scriptPath\repo\CyberArk"



#Set-Location "$env:C:\repo\Azure-DevOps\ProLab-IDM\CyberArk.PoshPACLI"
Set-Location "$scriptPath\repo\cyberark"

$files = Get-ChildItem -Path "$dataPath\OnboardAccounts\Archive\*.csv" -Name -Force
$files | Foreach-Object {
    $file = $_
    $filepath = Join-Path -Path "$dataPath\OnboardAccounts\Archive" -ChildPath $file
    .\DeleteAccounts.ps1 -ConfigPath "$scriptPath\Automation\DeletePendingAccounts.Config.json" `
        -inputpath $filepath 
}


