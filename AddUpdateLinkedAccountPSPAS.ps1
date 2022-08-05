#region About AddUpdateLinedAccountPSPAS.ps1
###########################################################################
# This script updates the ExtraPassSafe, ExtraPassName and ExtraPassFolder for given account(s)
#
#endregion
param (
    
    [Parameter(Mandatory=$false,HelpMessage="Please enter the local path for the config file")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[String]$ConfigPath="Sample_UpdateExtraPass_Config.json",
    [Parameter(Mandatory=$false)]
    [ScriptBlock]$Filter=$null 
)

. '.\Common.ps1'
$Executing = $MyInvocation.MyCommand.Name
LogMessage -message "********* Executing $Executing ***********"
$VaultConfig = (LoadJSONConfig -configpath $ConfigPath).VaultAuthorization
$config = (LoadJSONConfig -configpath $ConfigPath).AddUpdateLinkedAccountPSPAS
$files = $config.Files
if($null -eq $files -or ($files | Measure-Object).Count -eq 0){
    LogMessage -message "Files are not defined. Abort"
    return
}

$ExtraPassIndex = $config.ExtraPassIndex

if($null -eq $ExtraPassIndex){
    LogMessage -message "ExtraPassIndex is null!"
    return
}else{
    if($ExtraPassIndex -in "1","2","3"){
    }else{
        LogMessage -message "ExtraPassIndex is invalid! Must be 1, 2 or 3"
        return
    }
}




$appUserCred = PoSHPACLI_GetPassword -vaultname $VaultConfig.vaultname `
    -user $VaultConfig.gwuser `
    -logonfile $VaultConfig.logonfile `
    -sessionid $VaultConfig.sessionid `
    -vaultip $VaultConfig.vaultip `
    -pacliexe $VaultConfig.pacliexe `
    -targetsafe $VaultConfig.gwusersafe `
    -folder $VaultConfig.gwuserfolder `
    -objectname $VaultConfig.gwuserobjectname `
    -reason "Get app account to retrieve file '$filename'" -autoChangePassword $true




if($null -eq $appUserCred) {
    LogError -message "Could not get report app user credential!" 
    Throw "Could not get report app user credential!"  
    return
}

$appUsr = $VaultConfig.user.Trim()
$AppPwdC = $appUserCred.Password[1] # Not sure why this comes back as array and not string. Maybe b/c in my lab, account is not on platform policy 
$AppPwdC = $AppPwdC.Replace(" ","") 

$PwdC = ConvertTo-SecureString $AppPwdC -AsPlainText -Force

[pscredential]$cred = New-Object System.Management.Automation.PSCredential ($appUsr, $PwdC)
New-PASSession -Credential $cred -BaseURI $config.RESTAPI.BaseURL


<#
function PoSHPACLI_ConnectVault {
    param($VaultName,$Username,$LogonFile,$address,$sessionid, $pacliexe,[bool]$autoChangePassword=$false,[securestring]$password)
#>






$files | Foreach-Object {
    $filePath = $_
    $fileExists = $false
    if($null -eq $filePath -or $filePath -eq ""){
        LogMessage -message "File '$filePath' does not exist! Skipping."
    }else{
        $fileExists = Test-Path -Path $filePath

    }
    if($fileExists){
        $fileData = Import-Csv $filePath
        $fileData | ForEach-Object {
            $DataRow = $_
            $AccountId = $DataRow.id
            $ExtraPassName = $DataRow.ExtraPassName
            $ExtraPassFolder = $DataRow.ExtraPassFolder
            $ExtraPassSafe = $DataRow.ExtraPassSafe

            Set-PASLinkedAccount -id $AccountId -safe $ExtraPassSafe -folder $ExtraPassFolder -name $ExtraPassName -extraPasswordIndex $ExtraPassIndex


        }
        
    }else{
        LogMessage -message "File '$filePath' does not exist! Skipping."
    }
    
    

}




Close-PASSession
