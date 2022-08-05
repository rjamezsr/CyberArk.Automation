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

$masterConfig = Get-Content "$scriptPath\Automation\AccountOnboardingAutomation.json" | ConvertFrom-Json
if($null -ne $masterConfig.DisableSSLVerify -and $masterConfig.DisableSSLVerify -eq "Yes"){
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} ;
}


$files = Get-ChildItem -Path "$dataPath\OnboardAccounts\*.csv" -Name -Force
$files | Foreach-Object {
    $file = $_
    $filepath = Join-Path -Path "$dataPath\OnboardAccounts" -ChildPath $file
    .\Accounts_Onboard_Utility.ps1 -ConfigFile "$scriptPath\Automation\AccountOnboardingAutomation.json" `
        -CsvPath $filepath 
       
}


