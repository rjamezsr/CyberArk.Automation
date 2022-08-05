#region About GetFile.ps1
###########################################################################
# This script gets a file stored in a safe
#
#endregion
param (
    
    [Parameter(Mandatory=$false,HelpMessage="Please enter the local path for the config file")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[String]$ConfigPath="Sample_GetFile_Config.json",
    [Parameter(Mandatory=$false)]
    [ScriptBlock]$Filter=$null 
)

. '.\Common.ps1'

$Executing = $MyInvocation.MyCommand.Name
LogMessage -message "********* Executing $Executing ***********"
$currentUser = $env:UserName

$VaultConfig = (LoadJSONConfig -configpath $ConfigPath).VaultAuthorization

$config = (LoadJSONConfig -configpath $ConfigPath).GetFile


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




if($null -eq $appUserCred) {
    LogError -message "Could not get report app user credential!" 
    Throw "Could not get report app user credential!"  
    return
}

$appUsr = $VaultConfig.user.Trim()
$AppPwdC = $appUserCred.Password[1] # Not sure why this comes back as array and not string. Maybe b/c in my lab, account is not on platform policy 
$AppPwdC = $AppPwdC.Replace(" ","") 

$PwdC = ConvertTo-SecureString $AppPwdC -AsPlainText -Force



$items = $config.Files


if($null -ne $Filter){
    $items = $config.Files | Where-Object -FilterScript $Filter
}

$items | Foreach-Object {
    $item = $_
    $sourcepath = $item.sourcepath

    $localRelativefolder = Split-Path -Parent $sourcepath

    $localFolder = (Get-Item -Path $localRelativefolder).FullName
    

    $deleteFromSafe = $item.deleteFromSafe
    $filename = Split-Path $sourcepath -leaf

    $progressMoveFile = Show_Progress -progressObject $progressMoveFile -list $items -message "Getting file $filename"

    $fullPath = Join-Path -Path $localFolder -ChildPath $filename
    
    #$localFolder = (Split-Path -parent $fullPath) + "\"
    LogMessage -message "Getting file from vault '$filename'"

    $results = $null
    LogMessage -message "******* Getting file '$filename' *********"
    $results = PoSHPACLI_FindFile -VaultName $VaultConfig.vaultname `
        -Username $VaultConfig.user `
        -Password $PwdC -AsSecureString `
        -VaultIP $VaultConfig.vaultip `
        -SessionID $VaultConfig.sessionid `
        -PACLIEXE $VaultConfig.pacliexe `
        -TargetFolder $item.TargetFolder `
        -TargetSafeName $item.TargetSafe `
        -Pattern $filename
        

    $fullPath = Join-Path $localFolder -ChildPath $filename
    if($null -ne $fullPath -and $fullPath -ne ""){
        if(Test-Path -Path $fullPath){
            Remove-Item $fullPath
        }
    }

    if($null -ne $results){
        $removeFile = $false
        if($null -ne $deleteFromSafe -and $deleteFromSafe -ne ""){
            $removeFile = $deleteFromSafe -eq "Yes"
        }
        
        PoSHPACLI_GetFile -VaultName $VaultConfig.vaultname `
            -user $VaultConfig.user `
            -password $PwdC -AsSecureString `
            -vaultip  $VaultConfig.vaultip `
            -sessionid $VaultConfig.sessionid `
            -pacliexe $VaultConfig.pacliexe `
            -folder $item.TargetFolder `
            -targetsafe $item.TargetSafe `
            -filename $filename `
            -localFolder $localFolder `
            -deleteFromSafe $removeFile

        if(Test-Path -Path $fullPath){
            if((Get-Item $fullPath).length -eq 0){
                LogMessage -message "File '$fullPath' was downloaded, however, this file is empty!"   
            }
        }else{
            LogMessage -message "File '$fullPath' was NOT downloaded successfully!"
        }
    

    }else{
        LogError -message "File '$filename' does not exist in safe $TargetSafe"
    }
}