#region GetSafeMemberPermissions.ps1
###########################################################################
# This script reads object data from a CSV file and reports back descrepencies with safe members and safe member permissions
# This script depends on the psPAS module being installed. https://github.com/pspete/psPAS
# This script depends on the POSH-PACLI module being installed. https://github.com/pspete/PoShPACLI
#endregion
param (

    [Parameter(Mandatory=$false,HelpMessage="Please enter a valid Config file path")]
	[String]$ConfigPath="Sample_GetSafePermissions_Config.json"
    
)


. '.\Common.ps1'
. '.\Common.Roles.Config.ps1'

$Executing = $MyInvocation.MyCommand.Name
LogMessage -message "********* Executing $Executing ***********"
$currentUser = $env:UserName
$VaultConfig = (LoadJSONConfig -configpath $ConfigPath).VaultAuthorization
$RESTConfig = (LoadJSONConfig -configpath $ConfigPath).RESTAPI
$config = (LoadJSONConfig -configpath $ConfigPath).GetSafeRolePermissions
$rolesConfigFile = $config.rolesConfigFile
$SafeRolesConfiguration = Get-SafeRolePermissionsConfig -ConfigFile $rolesConfigFile
$Force = $config.Force -eq "Yes"
$ReportSafe = $config.Reports_Safe
$ReportFolder = $config.Reports_Folder


$allowAddMember = $config.allowAddMember
$allowUpdateMember = $config.allowUpdateMember
$allowDeleteMember = $config.allowDeleteMember

$outputDataFolder = $config.outputDataFolder

$PVWAURL = $RESTConfig.BaseURL
$authtype = $RESTConfig.authtype
$LogonURI = $PVWAURL+"/API/auth/$authtype/Logon"
$psPASBaseURL = $PVWAURL.Replace("/PasswordVault","")



$appUserCred = PoSHPACLI_GetPassword_Gateway -config $VaultConfig -reason $null -user $currentUser -script $Executing 
if($null -eq $appUserCred) {
    LogError -message "Could not get report app user credential!" 
    Throw "Could not get report app user credential!"
    return  
}
$appUsr = $VaultConfig.user.Trim()
$AppPwdC = $appUserCred.Password[1] # Not sure why this comes back as array and not string. Maybe b/c in my lab, account is not on platform policy 
$AppPwdC = $AppPwdC.Replace(" ","") 
$PwdC = ConvertTo-SecureString $AppPwdC -AsPlainText -Force



$appUserCredFiles = PoSHPACLI_GetPassword_Gateway -config $config.InputFile_Authorization -reason $null -user $currentUser -script $Executing 
if($null -eq $appUserCredFiles) {
    LogError -message "Could not get report app user credential!" 
    Throw "Could not get report app user credential!"
    return  
}
$appUsrFiles = $config.InputFile_Authorization.user.Trim()
$AppPwdCFiles = $appUserCredFiles.Password[1] # Not sure why this comes back as array and not string. Maybe b/c in my lab, account is not on platform policy 
$AppPwdCFiles = $AppPwdCFiles.Replace(" ","") 
$PwdCFiles = ConvertTo-SecureString $AppPwdCFiles -AsPlainText -Force





<#
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet
#>

$filename = Split-Path $config.inputfile -leaf
$localFolder = (Split-Path -parent $config.inputfile) + "\"
$InputFile_Safe  = $config.InputFile_Safe
$InputFile_Folder = $config.InputFile_Folder

$FindInputFileResult = PoSHPACLI_FindFile -VaultName $VaultConfig.vaultname `
    -Username $VaultConfig.user `
    -Password $PwdC -AsSecureString `
    -VaultIP $VaultConfig.vaultip `
    -SessionID $VaultConfig.sessionid `
    -PACLIEXE $VaultConfig.pacliexe `
    -Pattern $filename `
    -TargetSafeName $InputFile_Safe `
    -TargetFolder $InputFile_Folder
        
    
if($null -eq $FindInputFileResult){
    LogMessage -message "File '$filename' was not found in safe '$InputFile_Safe'"
    return
}



PoSHPACLI_GetFile -filename $filename `
    -localFolder $localFolder `
    -vaultname $config.InputFile_Authorization.vaultname `
    -user $config.InputFile_Authorization.user `
    -sessionid $config.InputFile_Authorization.sessionid `
    -vaultip $config.InputFile_Authorization.vaultip `
    -pacliexe $config.InputFile_Authorization.pacliexe `
    -targetsafe $InputFile_Safe `
    -folder $InputFile_Folder `
    -password $PwdCFiles -AsSecureString
    
    

$inputfile_Exists = $false
$inputfile = $config.inputfile
if($null -ne $inputfile -and $inputfile -ne ""){
    $inputfile_Exists = Test-Path $inputfile
}
if($inputfile_Exists -eq $false){
    LogError -message "inputfile was not downloaded and does not exist!"
    return
}

[pscredential]$cred = New-Object System.Management.Automation.PSCredential ($appUsr, $PwdC)
New-PASSession -Credential $cred -BaseURI $psPASBaseURL

$safeMemberData = Import-Csv -Path $inputfile  
$Safes = Import-Csv -Path $inputfile | Group-Object SafeName | Select-Object Name
$permissionChanges = [System.Collections.ArrayList]@()
$ignoreMembers = [System.Collections.ArrayList]@()

[void]$ignoreMembers.Add("administrator")
#[void]$ignoreMembers.Add("Vault Admins")
[void]$ignoreMembers.Add("Auditors")
[void]$ignoreMembers.Add("Backup Users")
[void]$ignoreMembers.Add("Batch")
[void]$ignoreMembers.Add("DR Users")
[void]$ignoreMembers.Add("Master")
[void]$ignoreMembers.Add("Notification Engines")
[void]$ignoreMembers.Add("Operators")
[void]$ignoreMembers.Add("AutomationApp")
[void]$ignoreMembers.Add("PSMAppUsers")


#pre-check

$Safes | ForEach-Object {
    
    $SafeName = $_.Name

    # Get-SafeRolePermissions -RoleName $_.Role -configuration $SafeRolesConfiguration
    $currentMembers = Get-PASSafeMember -SafeName $SafeName -includePredefinedUsers $true
    $expectedMembers = $safeMemberData | Where SafeName -eq $SafeName | Group-Object SafeMember | Select-Object Name

    #report unexpected members
    $currentMembers | Where Username -notin ($expectedMembers | Select Name).Name | ForEach-Object {
        if($_.Username -notlike "PasswordManager*" -and $_.Username -notin $ignoreMembers -and $_.Username -ne "Vault Admins"){
            [void]$permissionChanges.Add([PSCustomObject]@{
                SafeName = $SafeName;
                SafeMember = $_.Username;
                MemberType = "";
                Source = "";
                Change = "Not expected safe member. Should be removed";
                ExpectedRole = "";
                Permission ="";
                CurrentValue ="";
                ExpectedValue ="";
                Action = "Delete Member";
                Notes = "";
            })
        }
        
    }

    #report new members being added
    $expectedMembers | Where Name -notin ($currentMembers | Select Username).Username | Select Name | ForEach-Object {
        $SafeMember = $_.Name
        [void]$permissionChanges.Add([PSCustomObject]@{
            SafeName = $SafeName;
            SafeMember = $SafeMember;
            MemberType = ($safeMemberData | Where-Object {$_.SafeName -eq $SafeName -and $_.SafeMember -eq $SafeMember}).MemberType;
            Source = ($safeMemberData | Where-Object {$_.SafeName -eq $SafeName -and $_.SafeMember -eq $SafeMember}).Source;
            Change = "Member must be added.";
            ExpectedRole = ($safeMemberData | Where-Object {$_.SafeName -eq $SafeName -and $_.SafeMember -eq $SafeMember}).Role;
            Permission ="";
            CurrentValue ="";
            ExpectedValue ="";
            Action = "Create Member";
            Notes = "";
        })
    }
    
    $safeMemberData | Where-Object {$_.SafeName -eq $SafeName -and `
        $_.SafeMember -in ($currentMembers | Select Username).Username} | ForEach-Object {
        
        $SafeMember = $_.SafeMember
        $MemberType = $_.MemberType
        $Source = $_.Source 
        $ExpectedRole = $_.Role
        $expectedRoleName = $_.Role
        $expectedMemberPermissions = Get-SafeRolePermissions -RoleName $expectedRoleName -configuration $SafeRolesConfiguration
        $currentMemberPermissions = ($currentMembers | Where Username -eq $_.SafeMember | Select Permissions ).Permissions
        $expectedMemberPermissions | ForEach-Object {
            $Note = ""
            $match = $false
            $permission = $_.Name
            $currentAuthZLevel = "0"
            $Action = ""
            if($permission -eq "RequestsAuthorizationLevel"){
                $expectedValue = $_.Value
                if($currentMemberPermissions.requestsAuthorizationLevel1 -eq $true){
                    $currentAuthZLevel = "1"
                }elseif ($currentMemberPermissions.requestsAuthorizationLevel2 -eq $true) {
                    $currentAuthZLevel = "2"
                }
                $currentValue = $currentAuthZLevel
                if($expectedValue -eq "1" -or $expectedValue -eq "2"){
                    $Action = "Add permission"
                }else{
                    $Action = "Remove permission"
                }
            }else{
                $expectedValue = $_.Value -eq "true"
                $currentValue = $currentMemberPermissions.$permission
                if($expectedValue -eq $true){
                    $Action = "Add permission"
                }else{
                    $Action = "Remove permission"
                }
            }

            $match = $currentValue -eq $expectedValue
            if($match){
            }else{
                if($SafeMember -notlike "PasswordManager*" -and $SafeMember -notin $ignoreMembers -and $SafeMember -ne "Vault Admins"){
                    [void]$permissionChanges.Add([PSCustomObject]@{
                        SafeName = $SafeName;
                        SafeMember = $SafeMember;
                        MemberType = $MemberType;
                        Source = $Source;
                        Change = "Change in permission";
                        ExpectedRole = $ExpectedRole;
                        Permission ="$permission";
                        CurrentValue ="$currentValue";
                        ExpectedValue ="$expectedValue";
                        Action = $Action;
                        Notes = $Note;
                    })
                }

            }
        }
        
        
    }

}

$changeReportFile = "$outputDataFolder\\Exceptions_SafeMemberPermissions.csv"

$permissionChanges | Select SafeName,`
    SafeMember,MemberType,Source,Change,ExpectedRole,Permission,`
    CurrentValue,ExpectedValue,Action,Notes | `
    Export-Csv $changeReportFile -NoTypeInformation


Close-PASSession


$filetoUpload = $changeReportFile
$filetoUploadExists = $false
if($null -ne $filetoUpload -and $filetoUpload -ne ""){
    $filetoUploadExists = Test-Path $filetoUpload
}
if($filetoUploadExists){
    if($null -ne $ReportSafe -and $ReportSafe -ne ""){
        #Move file to safe
        LogMessage -message "File '$filetoUpload' created. Now moving file to vault"
        PoSHPACLI_UploadFile -VaultName $config.InputFile_Authorization.vaultname `
            -Usr $appUsrFiles `
            -password $PwdCFiles -AsSecureString `
            -VaultAddress $config.InputFile_Authorization.vaultip `
            -sessionid $config.InputFile_Authorization.sessionid `
            -PACLI_EXE $config.InputFile_Authorization.pacliexe `
            -TargetFolder $ReportFolder `
            -TargetSafe $ReportSafe `
            -inputpath $filetoUpload
        LogMessage -message "File '$filetoUpload' uploaded to vault. Now removing from local"
        Remove-Item $filetoUpload 
        if(Test-Path $filetoUpload){
            LogMessage -message "File '$filetoUpload' was not removed from local."
        }
    }
}

if($inputfile_Exists -eq $true){
    Remove-Item $inputfile
}