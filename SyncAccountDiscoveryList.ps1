#region About SyncAccountDiscoveryList.ps1
###########################################################################
# This script overwrites existing Unix server list stored in CyberArk for Unix Account Discovery
# NOTE: Example of inputpath CSV file

#endregion
param (
    
    [Parameter(Mandatory=$false,HelpMessage="Please enter path to Config file")]
	[String]$AccountsFeedConfigPath="Sample_Accounts_Feed_Config.json",
    [Parameter(Mandatory=$false)]
    [ScriptBlock]$Filter=$null 
)

. '.\Common.ps1'
$Executing = $MyInvocation.MyCommand.Name
LogMessage -message "********* Executing $Executing ***********"
$currentUser = $env:UserName
LogMessage -message "Start Sync Account Discovery List"
$VaultConfig = (LoadJSONConfig -configpath $AccountsFeedConfigPath).VaultAuthorization
$config = (LoadJSONConfig -configpath $AccountsFeedConfigPath).UploadFile
if($null -eq $config -or $config.Length -eq 0 -or $null -eq $VaultConfig -or $VaultConfig.Length -eq 0){
    LogError -message "Could not load config file '$AccountsFeedConfigPath'"
    return
}
LogMessage -message "Getting pacli credentials from vault"
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
    $Items = $config.Files | Where-Object -FilterScript $Filter
}
$items | Foreach-Object {
    $item = $_
    $sourcefile = $item.sourcepath
    $WorkingDirectory = $item.WorkingDirectory
    $sourceFileExists = $false
    $WorkingDirectoryExists = $false
    if($null -ne $sourceFile -and $null -ne $WorkingDirectory){
        $sourceFileExists = Test-Path $sourcefile
        $WorkingDirectoryExists = Test-Path $WorkingDirectory    
    }
    if($sourceFileExists -eq $false -or $WorkingDirectoryExists -eq $false){
        $sourceFile = $item.sourcepath
        LogError -message "Source file '$sourceFile' does not exist or Working directory '$WorkingDirectory' does not exist. Skipping"
    }else{
        LogMessage -message "Uploading file '$sourcefile'"
        $outputFile = Split-Path $sourcefile -leaf
        $Pattern = ($outputFile.Split("."))[0] + "*"
        LogMessage -message "Searching for file with pattern '$Pattern'"    
        $result = PoSHPACLI_FindFile -Pattern $Pattern `
            -TargetSafeName $item.targetsafe `
            -TargetFolder $item.targetfolder `
            -Username $VaultConfig.user `
            -password $PwdC -AsSecureString `
            -VaultIP $VaultConfig.vaultip `
            -SessionID $VaultConfig.sessionid `
            -PACLIEXE $VaultConfig.pacliexe `
            -VaultName $VaultConfig.vaultname
        $MultipleFiles = $false
        $FileFound = ($null -ne $result -and $result.Length -gt 0)
        if($FileFound -eq $false){
            LogError -message "No files found with pattern '$Pattern'"
        }else{
            if($result.Length -gt 1){
                $Files = $result | Group-Object -Property Filename
                $MultipleFiles = $Files.Length -gt 1
            }
            $updateAll = ($null -ne $item.updateall -and $item.updateall -eq "Yes")
            if($MultipleFiles -and $updateAll -eq $false){
                LogError -message "Cannot sync file. Pattern match resulted in more than one file found in the safe."
            }else{
                $Files | ForEach-Object {
                    $uploadFile = $_.Name
                    #$folderpath = Split-Path $item.sourcepath
                    #$destinationPath = Join-Path -Path $folderpath -ChildPath $uploadFile
                    $destinationPath = Join-Path -Path $WorkingDirectory -ChildPath $uploadFile
                    LogMessage -message "Copying file to '$destinationPath' "
                    Copy-Item $item.sourcepath -Destination $destinationPath
                    LogMessage -message "Uploading file '$uploadFile' to vault..."
                    PoSHPACLI_UploadFile -VaultName $VaultConfig.vaultname `
                            -Usr $VaultConfig.user `
                            -password $PwdC -AsSecureString `
                            -VaultAddress $VaultConfig.vaultip `
                            -sessionid $VaultConfig.sessionid `
                            -PACLI_EXE $VaultConfig.pacliexe `
                            -TargetFolder $item.targetfolder `
                            -TargetSafe $item.targetsafe `
                            -inputpath $destinationPath
                    Remove-Item -Path $destinationPath
                    LogMessage -message "Done uploading file '$uploadFile' to vault"
                }
            }
        }
    }
}
