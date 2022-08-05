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


Set-Location "$scriptPath\repo\cyberark"

$masterConfig = Get-Content "$scriptPath\Automation\AccountOnboardingAutomation.json" | ConvertFrom-Json
if($null -ne $masterConfig.DisableSSLVerify -and $masterConfig.DisableSSLVerify -eq "Yes"){
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} ;
}

.\GetAccountsRESTAPI.ps1 -ConfigPath "$scriptPath\Automation\AccountOnboardingAutomation.json"
.\GetFile.ps1 -ConfigPath "$scriptPath\Automation\AccountOnboardingAutomation.json"
.\DeleteAccounts.ps1 -ConfigPath "$scriptPath\Automation\AccountOnboardingAutomation.json"

