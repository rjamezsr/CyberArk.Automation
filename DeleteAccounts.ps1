#region About DeleteAccounts.ps1
###########################################################################
# This script reads pending account data from CSV file and deletes the object from the target safe
# NOTE, here example CSV file
<#
Filename
----------------------------------------
server1-administartor-mysafe-myplatform

#>
#endregion  
param (
    
    [Parameter(Mandatory=$false,HelpMessage="Please enter your Config file location (For example: c:\files\file1.json)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[String]$ConfigPath="Sample_DeleteAccounts_Config.json",

    [Parameter(Mandatory=$false,HelpMessage="Please enter your CSV file location address (For example: c:\files\file1.csv)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[String]$inputpath=$null,

    [Parameter(Mandatory=$false,HelpMessage="Please enter the Safe Name to use as an override")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[String]$SafeName=$null,
    
    [Parameter(Mandatory=$false,HelpMessage="Please enter the folder to use as an override")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[String]$Folder=$null

    
)

# $CommonScriptParent = Split-Path -Path (Split-Path -Path $MyInvocation.MyCommand.Definition -Parent) -Parent
# . ($CommonScriptParent + '.\CyberArk.Common\CyberArk.Common\Common.ps1')


# . "C:\repo\Azure-devops\ProLab-IDM\CyberArk.Common\CyberArk.Common\CyberArk.Common\Common.ps1"
. '.\Common.ps1'
. '.\Common.DataValidations.ps1'

$Executing = $MyInvocation.MyCommand.Name
LogMessage -message "********* Executing $Executing ***********"
$currentUser = $env:UserName

#$SafeName = "PasswordManager_Pending"
#$Folder = "root"


$VaultConfig = (LoadJSONConfig -configpath $ConfigPath).VaultAuthorization
$configItems = (LoadJSONConfig -configpath $ConfigPath).DeleteAccounts | Where-Object {$_.Enabled -eq "true"}
if(($configItems | Measure).Count -eq 0){
    LogMessage -message "There are no DeleteAccount configurations enabled. Aborting."
    return
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


PoSHPACLI_ConnectVault -VaultName $VaultConfig.vaultname `
    -Username $VaultConfig.user `
    -Password $PwdC `
    -address $VaultConfig.vaultip `
    -sessionid $VaultConfig.sessionid `
    -pacliexe $VaultConfig.pacliexe


$configItems | ForEach-Object {
    $config = $_
    $files = $config.Files
    $filesFolder = $config.FilesFolder
    $DeleteFile = $config.DeleteFile -eq "true"
    $SafeNameOverride = $config.SafeNameOverride

    if($null -eq $inputpath -or $inputpath.Length -eq 0){
        if($null -eq $files -or $files.Length -eq 0){
            LogMessage -message "No files specified in config."
        }
        if($null -eq $filesFolder -or $filesFolder.Length -eq 0){
            LogMessage -message "No files folder specified in config."
        }else{
            if(Test-Path -Path $filesFolder){
                $files = [System.Collections.ArrayList]@()
                $folderFormat = "{0}\*.csv"
                $filePathFormat = "{0}\{1}"
                $folderPath = $folderFormat -f $filesFolder
                Get-ChildItem -Path $folderPath -Name -Force | Foreach-Object {
                    $filePath = $filePathFormat -f $filesFolder, $_
                    [void]$files.Add([PSCustomObject]@{sourcepath = $filePath})            
                }
            }
        }

    }else{
        LogMessage -message "Configure overide with source path '$inputpath'"
        $files = $null
        $files = @([PSCustomObject]@{sourcepath = $inputpath})
    }

    $files | ForEach-Object {
        $sourceFileExists = $false
        $TargetSafeName = ""
        $SafeNameOverridden = $false
        $SafeNameOverriddenFromParameter = $false
        if($null -ne $_.sourcepath){
            $sourceFileExists = Test-Path $_.sourcepath
        }else{
            LogMessage -message "Source file in configuration file is null!"
        }
        if($sourceFileExists){
            $filelist = Import-Csv -Path $_.sourcepath
            if($null -ne $SafeName -and $SafeName -ne ""){
                LogMessage -message "Override safe name from parameter"
                $SafeNameOverriddenFromParameter = $true
                $safes = @([pscustomobject]@{Name=$SafeName;})
            }else{
                if($null -ne $SafeNameOverride -and $SafeNameOverride -ne "" -and ($null -eq $SafeName -or $SafeName -eq "")){
                    LogMessage -message "Override safe name from config file"
                    $SafeNameOverridden = $true
                    $safes = @([pscustomobject]@{Name=$SafeNameOverride;})
                }else{
                    $safes = $filelist | Group-Object -Property safeName
                }
            }
            
            if(($safes | measure).Count -eq 0){
                LogMessage -message "There are NO safes with accounts to delete in this file"
            }
            $safes | ForEach-Object {
                $TargetSafeName = $_.Name
                $KeyField = $config.Key


                PoSHPACLI_OpenSafe -SafeName $TargetSafeName
                if(($filelist | measure).Count -eq 0){
                    LogMessage -message "There are NO accounts to delete in this file"
                }
                if($SafeNameOverridden -or $SafeNameOverriddenFromParameter){
                    $filelist | Foreach-Object {
                        $ObjectName = $_.$KeyField
                        $progressDeleteObject = Show_Progress -progressObject $progressDeleteObject -list $filelist -message "Deleting object $ObjectName"
                        PoSHPACLI_DeleteObject -SafeName $TargetSafeName -Folder $config.TargetFolder -ObjectName $ObjectName
                    }
                }else{
                    $filelist | Where-Object { $_.SafeName -eq $TargetSafeName} | Foreach-Object {
                        $ObjectName = $_.$KeyField
                        $progressDeleteObject = Show_Progress -progressObject $progressDeleteObject -list $filelist -message "Deleting object $ObjectName"
                        PoSHPACLI_DeleteObject -SafeName $TargetSafeName -Folder $config.TargetFolder -ObjectName $ObjectName
                    }
                }


                
                PoSHPACLI_CloseSafe -SafeName $TargetSafeName
            }
            if($DeleteFile){
                LogMessage -message "Delete options complete. Deleting file..."
                try {
                    Remove-Item $_.sourcepath
                    LogMessage -message "File deleted."
                }catch {
                    $msg =  $Error[0]
                    LogError -message $msg 
                }
                
            }
        }else{
            LogMessage -message "Source file is null or does not exist. Will not delete objects."
        }
    }

}


PoSHPACLI_CloseSafe -SafeName $config.TargetSafe
PoSHPACLI_DisconnectVault

