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

.\GetFile.ps1 -ConfigPath "$scriptPath\Automation\AccountOnboardingAutomation.json"
