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

.\GetFile.ps1 -ConfigPath "$scriptPath\Automation\AccountOnboardingAutomation.json"
.\QueryCMDB.ps1 -CMDBConfigPath "$scriptPath\Automation\AccountOnboardingAutomation.json"
