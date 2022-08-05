#region About AddUpdatePlatforms.ps1
###########################################################################
# This script connects to CyberArk REST API and updates platforms
#


###########################################################################
#>
#endregion
param (
    [Parameter(Mandatory=$false,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL="",

    #[String]$PVWAURL="https://cyberarkdemo.westus.cloudapp.azure.com/PasswordVault",

    [Parameter(Mandatory=$false,HelpMessage="Please enter the safe name")]
	[String]$TargetSafe="",

    [Parameter(Mandatory=$false,HelpMessage="Please enter the folder name")]
	[String]$TargetFolder="",
    
    [Parameter(Mandatory=$false,HelpMessage="Please enter the file path for the report")]
	[String]$sourcepath="",

    [Parameter(Mandatory=$false,HelpMessage="Please enter the name of the safe to store the report")]
	[String]$Reports_Safe="",

    [Parameter(Mandatory=$false,HelpMessage="Please enter the name of the safe folder to store the report")]
	[String]$Reports_Folder="",

    [Parameter(Mandatory=$false,HelpMessage="Please specify if the report will be force created (re-created) if exists")]
	[String]$ForceReportCreation="",

    [Parameter(Mandatory=$false)]
    [String]$authtoken,

    [Parameter(Mandatory=$false)]
    [String]$authtype="",
    
    [Parameter(Mandatory=$false)]
    [String]$safeListRef="",
    

    [Parameter(Mandatory=$false)]
    [String]$ConfigPath="AddUpdatePlatforms.Config.json"
    
    
)
. '.\Common.ps1'


$Executing = $MyInvocation.MyCommand.Name
LogMessage -message "********* Executing $Executing ***********"
$currentUser = $env:UserName


$ConfigFileExists = Test-Path $ConfigPath
$SuppliedCredentials = $false

if($null -ne $Usr -and $Usr.Length -ne 0 -and $null -ne $PwdC -and $PwdC.Length -ne 0){
    $SuppliedCredentials = $true
}

if($ConfigFileExists -eq $false -and $SuppliedCredentials -eq $false){
    LogMessage -message "Credentials were not provided and there is no config file or config file does not exist. Config file path '$ConfigPath'"
    LogMessage -message "Aborting"
    return
}

if($ConfigFileExists){
    $configContent = LoadJSONConfig -configpath $ConfigPath
    $config = $configContent.AddUpdatePlatforms
    $VaultConfig = $configContent.VaultAuthorization
    $RESTAPIConfig = $configContent.RESTAPI
    LogMessage -message "Config file loaded '$ConfigPath'"
}else{
    LogMessage -message "No config file specified or config file does not exist."
}

if($SuppliedCredentials){
    LogMessage -message "Overriding configuration for vault credentials. Using supplied credential."
    $appUsr = $Usr
}else{
    LogMessage -message "No credential override was supplied. Using credentials configured in the configuration file."
}

if($null -eq $config -or $null -eq $VaultConfig){
    LogError -message "Could not load config file '$ConfigPath'"
    return
}

$Token = $null

if($SuppliedCredentials -eq $false){
    LogMessage -message "Getting pacli credentials from vault"
    #get app user cred
    $appUserCred = $null
    $appUserCred = PoSHPACLI_GetPassword -vaultname $VaultConfig.vaultname `
        -user $VaultConfig.gwuser `
        -logonfile $VaultConfig.logonfile `
        -sessionid $VaultConfig.sessionid `
        -vaultip $VaultConfig.vaultip `
        -pacliexe $VaultConfig.pacliexe `
        -targetsafe $VaultConfig.gwusersafe `
        -folder $VaultConfig.gwuserfolder `
        -objectname $VaultConfig.gwuserobjectname `
        -reason "Executing $Executing as user $currentUser" -autoChangePassword $true
    
    if($null -eq $appUserCred.Password) {
        LogError -message "Could not get report app user credential! Aborting." 
        return
    }
    
    $appUsr = $VaultConfig.user.Trim()
    $AppPwdC = $appUserCred.Password[1] # Not sure why this comes back as array and not string. Maybe b/c in my lab, account is not on platform policy
    $AppPwdC = $AppPwdC.Replace(" ","") 
    $PwdC = ConvertTo-SecureString $AppPwdC -AsPlainText -Force

}

$AuthZHeader = $null

if($null -eq $PVWAURL -or $PVWAURL.Length -eq 0){
    LogMessage -message "No URL override provided. Checking config."
    if($null -eq $configContent.RESTAPI.BaseURL -or $configContent.RESTAPI.BaseURL.Length -eq 0){
        LogMessage -message "No URL override provided nor defined in a config. Aborting."
        return
    }else{

        $PVWAURL = $configContent.RESTAPI.BaseURL
        $authtype = $configContent.RESTAPI.authtype
        $LogonUri = $PVWAURL+"/PasswordVault/API/auth/$authtype/Logon"
        LogMessage -message "PVWAURL provided by config '$PVWAURL'"   
    }
}else{
    LogMessage -message "PVWAURL override provided."   
}

[pscredential]$cred = New-Object System.Management.Automation.PSCredential ($appUsr, $PwdC)


if($configContent.DisableSSLVerify -eq "Yes"){
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
}

if(($config.Platforms | Measure-Object).Count -gt 0){

    New-PASSession -Credential $cred -BaseURI $PVWAURL
    $config.Platforms | ForEach-Object {
        $ZipFileLocation = $_.ZipFileLocation
        $AllowOverwrite = $_.AllowOverwrite -eq "Yes"
        $AllowCopy = $_.AllowCopy -eq "Yes"
        $PolicyID = $_.PolicyID
        $currentPlatform = $null 
        $ZipFileExists = $false
        $CannotOverwriteNorCopy = ($AllowOverwrite -eq $false -and $AllowCopy -eq $false)
        if($null -ne $ZipFileLocation -and $ZipFileLocation -ne ""){
            $ZipFileExists = Test-Path -Path $ZipFileLocation
        }


        if($ZipFileExists){
            try {
                $currentPlatform = Get-PASPlatform -PlatformID $PolicyID
            } catch {
    
            }
            
            if($null -eq $currentPlatform){
                LogMessage -message "Platform DOES not exist. Importing new platform '$PolicyID'"
            }else{
                LogMessage -message "Platform exists"
                if($CannotOverwriteNorCopy){
                    LogMessage -message "Cannot duplicate nor update platform '$PolicyID'. Both AllowOverwrite and AllowCopy are No."
                }else{
                    if($AllowOverwrite){
                        LogMessage -message "Overwriting platform '$PolicyID'"
                    }else{
                        LogMessage -message "Duplicating platform '$PolicyID'"
                    }
                }
    
    
    
    
            }
        }else{
            LogMessage -message "Zip file '$ZipFileLocation' does not exist!"
        }
        


    }
    Close-PASSession 
}

