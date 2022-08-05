
#region About Common.ps1
###########################################################################
# Collection of functions used to run commands in CyberArk Vault
# Dependencies:
#endregion
#region Define URIs
$LogonUri               = $PVWAURL+"/API/auth/$authtype/Logon"
$LogoffUri              = $PVWAURL+'/API/Auth/Logoff'
$FindGroupURI           = $PVWAURL+'/api/UserGroups?{0}'
$AddGroupURI            = $PVWAURL+'/api/UserGroups'
$UpdateGroupURI         = $PVWAURL+'/api/UserGroups/{0}'
$GetSafesURI            = $PVWAURL+'/WebServices/PIMServices.svc/Safes'
$GetSafesAPIURI         = $PVWAURL+'/api/safes'
$SearchSafes            = $PVWAURL+'/WebServices/PIMServices.svc/Safes?query={0}'
$GetSafeDetailsAPIURI   = $PVWAURL+'/api/safes?search={0}&extendedDetails={1}&includeAccounts={2}'
$AddSafeMemberURI       = $PVWAURL+'/WebServices/PIMServices.svc/Safes/{0}/Members'
$DeleteSafeMemberURI       = $PVWAURL+'/WebServices/PIMServices.svc/Safes/{0}/Members/{1}'

$UpdateSafeMemberURI    = $PVWAURL+'/WebServices/PIMServices.svc/Safes/{0}/Members/{1}'
$SearchMembersURI       = $PVWAURL+'/WebServices/PIMServices.svc/Safes/{0}/Members'
$AddGroupMember         = $PVWAURL+'/api/UserGroups/{0}/Members/'
$RemoveGroupMember      = $PVWAURL+'/api/UserGroups/{0}/Members/{1}'
$FindUser               = $PVWAURL+'/api/Users?{0}'
$CreateCyberArkSafeURI  = $PVWAURL+"/WebServices/PIMServices.svc/Safes"
$CreateCyberArkSafeURI2 = $PVWAURL+"/api/safes"
$GetAccountsURI         = $PVWAURL+'/api/Accounts?filter=safeName eq {0}'
$GetPasswordURI         = $PVWAURL+'/api/Accounts/{0}/Password/Retrieve'
$GetPlatformsURI        = $PVWAURL+'/API/Platforms'
$GetPlatformDetailsURI  = $PVWAURL+'/API/Platforms/{0}'

$ActionAddGroupMember       = "add"
$ActionRemoveGroupMember    = "remove"
$MaxSafeNameLength          = 28
$MinSafeNameLength          = 5
#$DisableSSLVerify           = $null
$DisableSSLVerifyOption     = $null
#endregion

#region Define logging
$CurrentLocation                    = Get-Location
$logfolder                          = "$CurrentLocation\logs\"
$del1                               = ","
$ScriptErrorFile                    = $logfolder + "error.csv"
$ScriptErrorFile_format             = "{0}$del1{1}"
$ScriptErrorFile_header             = $ScriptErrorFile_format -f "Date","Error"

$Log                                = $logfolder + "log.csv"
$Log_format                         = "{0}$del1{1}"
$Log_header                         = $Log_format -f "Date","Action"
$ObjectLevelErrorFile               = $logfolder +"error_object.csv"
$ObjectLevelErrorFile_object_format = "{0}$del1{1}$del1{2}$del1{3}"
$ObjectLevelErrorFile_object_header = $ObjectLevelErrorFile_object_format -f "Date","Username","Address","Error"

if (-not (Test-Path $logfolder)){
    New-Item $logfolder -ItemType "directory" -Force
}

if (-not (Test-Path $Log)){
    New-Item $Log
    $Log_header | Out-File -FilePath $Log
}
if (-not (Test-Path $ScriptErrorFile)){
    New-Item $ScriptErrorFile
    $ScriptErrorFile_header | Out-File -FilePath $ScriptErrorFile
}
if (-not (Test-Path $ObjectLevelErrorFile)){
    New-Item $ObjectLevelErrorFile
    $ObjectLevelErrorFile_object_header | Out-File -FilePath $ObjectLevelErrorFile
}
#endregion

#region define FileList variables
$FileListOutputHeader = "UserName,Address,AccountDiscoveryDate,AccountEnabled,AccountOSGroups,DiscoveryPlatformType,LastPasswordSetDate,LastLogonDate,PasswordNeverExpires,AccountExpirationDate,OSVersion,AccountCategory,MachineOSFamily,AccountType,CreationMethod,Dependencies,Domain,UserDisplayName,OU,SID,UID,GID,Fingerprint,Length,Path,Format,Comment,Encryption,DeviceType,Safe,Folder,Filename,TargetSafeName,TargetPlatformId,IP"
$FileListOutputFormat = '"{0}","{1}","{2}","{3}","{4}","{5}","{6}","{7}","{8}","{9}","{10}","{11}","{12}","{13}","{14}","{15}","{16}","{17}","{18}","{19}","{20}","{21}","{22}","{23}","{24}","{25}","{26}","{27}","{28}","{29}","{30}","{31}","{32}","{33}","{34}"'
$FileListOutputDelimiter = ","
#endregion

function ValidateSafeNameLength {
    param($safename)
    $Valid = $false
    $LenOfSafeName = $safename.length
    
    if($LenOfSafeName -gt $MaxSafeNameLength -or $LenOfSafeName -lt $MinSafeNameLength){
        $msg = "Length of safe name '$SafeName' is invalid. Must be between $MinSafeNameLength and $MaxSafeNameLength characters long"
        LogError -message $msg
        Throw $msg
        $Valid = $false
    }else{
        $Valid = $true
    }
    return $Valid
}

function LogError {
    param($message)
    $DateTime = Get-Date
    $Msg = "{0}$del1{1}" -f $DateTime,$message
    $Msg | Out-File -FilePath $ScriptErrorFile -Append
    Write-Verbose $message
}
function GetFileName {
    param([string]$Filepath,[switch]$NewFileName,[switch]$ReturnFullpath)
    $result = $null
    if(-not ($NewFileName) -and $ReturnFullpath){return $Filepath}
    $fileNameOnly = [io.path]::GetFileNameWithoutExtension($Filepath)
    $fileExtension = [System.IO.Path]::GetExtension($Filepath)
    $result = "$fileNameOnly$fileExtension"
    if($NewFileName){
        $Directory = Split-Path -Path $Filepath
        $cnt = 1
        $fileExists = Test-Path -Path $Filepath
        if ($fileExists){
            While ($fileExists -eq $true)
            {
                $changedFileName = "$fileNameOnly$cnt$fileExtension"
                $Filepath = "$Directory\$changedFileName"
                $fileExists = Test-Path -Path $Filepath
                $cnt = $cnt + 1

            } 
        }
        $result = $changedFileName
        if($ReturnFullpath){$result = $Filepath}
    }

    return $result
}
function LogMessage {
    param($message)
    $LogMsg = "{0}$del1{1}"
    $DateTime = Get-Date
    $LogMsg = $LogMsg -f $DateTime,$message
    $LogMsg | Out-File -FilePath $Log -Append 
    Write-Verbose $message
}
function LogObjectError {
    param($message)
    $DateTime = Get-Date
    $Msg = "{0}$del1{1}$del1{2}$del1{3}$del1" -f $DateTime,$FileCat_UserName,$FileCat_Address,$message
    $Msg | Out-File -FilePath $ObjectLevelErrorFile -Append
    Write-Verbose $message
}
Function GenerateSafeMemberJSON {
    param($membername,$configpath,$searchin="")
    LogMessage -message "Adding member $membername"
    $PermissionsData = Get-Content -Path $configpath | ConvertFrom-Json
    if($searchin -eq ""){
        $searchin = "Vault"
    }
    $perm = @(
            [PSCustomObject]@{Key = "UseAccounts";Value = ($PermissionsData.UseAccounts -eq "true")},
            [PSCustomObject]@{Key = "RetrieveAccounts";Value = ($PermissionsData.RetrieveAccounts -eq "true")},
            [PSCustomObject]@{Key = "ListAccounts";Value = ($PermissionsData.ListAccounts -eq "true")},
            [PSCustomObject]@{Key = "AddAccounts";Value = ($PermissionsData.AddAccounts -eq "true")},
            [PSCustomObject]@{Key = "UpdateAccountContent";Value = ($PermissionsData.UpdateAccountContent -eq "true")},
            [PSCustomObject]@{Key = "UpdateAccountProperties";Value = ($PermissionsData.UpdateAccountProperties -eq "true")},
            [PSCustomObject]@{Key = "InitiateCPMAccountManagementOperations";Value = ($PermissionsData.InitiateCPMAccountManagementOperations -eq "true")},
            [PSCustomObject]@{Key = "SpecifyNextAccountContent";Value = ($PermissionsData.SpecifyNextAccountContent -eq "true")},
            [PSCustomObject]@{Key = "RenameAccounts";Value = ($PermissionsData.RenameAccounts -eq "true")},
            [PSCustomObject]@{Key = "DeleteAccounts";Value = ($PermissionsData.DeleteAccounts -eq "true")},
            [PSCustomObject]@{Key = "UnlockAccounts";Value = ($PermissionsData.UnlockAccounts -eq "true")},
            [PSCustomObject]@{Key = "ManageSafe";Value = ($PermissionsData.ManageSafe -eq "true")},
            [PSCustomObject]@{Key = "ManageSafeMembers";Value = ($PermissionsData.ManageSafeMembers -eq "true")},
            [PSCustomObject]@{Key = "BackupSafe";Value = ($PermissionsData.BackupSafe -eq "true")},
            [PSCustomObject]@{Key = "ViewAuditLog";Value = ($PermissionsData.ViewAuditLog -eq "true")},
            [PSCustomObject]@{Key = "ViewSafeMembers";Value = ($PermissionsData.ViewSafeMembers -eq "true")},
            [PSCustomObject]@{Key = "RequestsAuthorizationLevel";Value = [int]$PermissionsData.RequestsAuthorizationLevel},
            [PSCustomObject]@{Key = "AccessWithoutConfirmation";Value = ($PermissionsData.AccessWithoutConfirmation -eq "true")},
            [PSCustomObject]@{Key = "CreateFolders";Value = ($PermissionsData.CreateFolders -eq "true")},
            [PSCustomObject]@{Key = "DeleteFolders";Value = ($PermissionsData.DeleteFolders -eq "true")},
            [PSCustomObject]@{Key = "MoveAccountsAndFolders";Value = ($PermissionsData.MoveAccountsAndFolders -eq "true")}
    )
    if($membername -eq ""){
        $json = [PSCustomObject]@{member = @{
            Permissions = $perm
        } } | ConvertTo-Json -Depth 4 -Compress
    }else{
        $json = [PSCustomObject]@{member = @{
            MemberName = "$membername";
            SearchIn = "$searchin";
            Permissions = $perm
        } } | ConvertTo-Json -Depth 4 -Compress
    }
    return $json

}
function GetSafeUserPermissionsJSON{
    param($groupname) 

    $perm = @(
            [PSCustomObject]@{Key = "UseAccounts";Value = $true},
            [PSCustomObject]@{Key = "RetrieveAccounts";Value = $true},
            [PSCustomObject]@{Key = "ListAccounts";Value = $true},
            [PSCustomObject]@{Key = "AddAccounts";Value = $false},
            [PSCustomObject]@{Key = "UpdateAccountContent";Value = $false},
            [PSCustomObject]@{Key = "UpdateAccountProperties";Value = $false},
            [PSCustomObject]@{Key = "InitiateCPMAccountManagementOperations";Value = $false},
            [PSCustomObject]@{Key = "SpecifyNextAccountContent";Value = $false},
            [PSCustomObject]@{Key = "RenameAccounts";Value = $false},
            [PSCustomObject]@{Key = "DeleteAccounts";Value = $false},
            [PSCustomObject]@{Key = "UnlockAccounts";Value = $false},
            [PSCustomObject]@{Key = "ManageSafe";Value = $false},
            [PSCustomObject]@{Key = "ManageSafeMembers";Value = $false},
            [PSCustomObject]@{Key = "BackupSafe";Value = $false},
            [PSCustomObject]@{Key = "ViewAuditLog";Value = $true},
            [PSCustomObject]@{Key = "ViewSafeMembers";Value = $true},
            [PSCustomObject]@{Key = "RequestsAuthorizationLevel";Value = 0},
            [PSCustomObject]@{Key = "AccessWithoutConfirmation";Value = $false},
            [PSCustomObject]@{Key = "CreateFolders";Value = $false},
            [PSCustomObject]@{Key = "DeleteFolders";Value = $false},
            [PSCustomObject]@{Key = "MoveAccountsAndFolders";Value = $false}
        )
    
    if($groupname -eq ""){
        $json = [PSCustomObject]@{member = @{
            Permissions = $perm
        } } | ConvertTo-Json -Depth 4 -Compress
    }else{
        $json = [PSCustomObject]@{member = @{
            MemberName = "$groupname";
            SearchIn = "Vault";
            Permissions = $perm
        } } | ConvertTo-Json -Depth 4 -Compress
    }
    return $json
}
function GetSafeOwnerPermissionsJSON{
    param($groupname) 

    $perm = @(
            [PSCustomObject]@{Key = "UseAccounts";Value = $true},
            [PSCustomObject]@{Key = "RetrieveAccounts";Value = $true},
            [PSCustomObject]@{Key = "ListAccounts";Value = $true},
            [PSCustomObject]@{Key = "AddAccounts";Value = $false},
            [PSCustomObject]@{Key = "UpdateAccountContent";Value = $true},
            [PSCustomObject]@{Key = "UpdateAccountProperties";Value = $true},
            [PSCustomObject]@{Key = "InitiateCPMAccountManagementOperations";Value = $true},
            [PSCustomObject]@{Key = "SpecifyNextAccountContent";Value = $true},
            [PSCustomObject]@{Key = "RenameAccounts";Value = $false},
            [PSCustomObject]@{Key = "DeleteAccounts";Value = $false},
            [PSCustomObject]@{Key = "UnlockAccounts";Value = $true},
            [PSCustomObject]@{Key = "ManageSafe";Value = $false},
            [PSCustomObject]@{Key = "ManageSafeMembers";Value = $false},
            [PSCustomObject]@{Key = "BackupSafe";Value = $false},
            [PSCustomObject]@{Key = "ViewAuditLog";Value = $true},
            [PSCustomObject]@{Key = "ViewSafeMembers";Value = $true},
            [PSCustomObject]@{Key = "RequestsAuthorizationLevel";Value = 1},
            [PSCustomObject]@{Key = "AccessWithoutConfirmation";Value = $false},
            [PSCustomObject]@{Key = "CreateFolders";Value = $false},
            [PSCustomObject]@{Key = "DeleteFolders";Value = $false},
            [PSCustomObject]@{Key = "MoveAccountsAndFolders";Value = $false}
    )
    if($groupname -eq ""){
        $json = [PSCustomObject]@{member = @{
            Permissions = $perm
        } } | ConvertTo-Json -Depth 4 -Compress
    }else{
        $json = [PSCustomObject]@{member = @{
            MemberName = "$groupname";
            SearchIn = "Vault";
            Permissions = $perm
        } } | ConvertTo-Json -Depth 4 -Compress
    }

    return $json
}
function GetSafeAdminPermissionsJSON{
    param($groupname) 


    $perm = @(
            [PSCustomObject]@{Key = "UseAccounts";Value = $true},
            [PSCustomObject]@{Key = "RetrieveAccounts";Value = $true},
            [PSCustomObject]@{Key = "ListAccounts";Value = $true},
            [PSCustomObject]@{Key = "AddAccounts";Value = $false},
            [PSCustomObject]@{Key = "UpdateAccountContent";Value = $true},
            [PSCustomObject]@{Key = "UpdateAccountProperties";Value = $true},
            [PSCustomObject]@{Key = "InitiateCPMAccountManagementOperations";Value = $true},
            [PSCustomObject]@{Key = "SpecifyNextAccountContent";Value = $true},
            [PSCustomObject]@{Key = "RenameAccounts";Value = $true},
            [PSCustomObject]@{Key = "DeleteAccounts";Value = $true},
            [PSCustomObject]@{Key = "UnlockAccounts";Value = $true},
            [PSCustomObject]@{Key = "ManageSafe";Value = $true},
            [PSCustomObject]@{Key = "ManageSafeMembers";Value = $false},
            [PSCustomObject]@{Key = "BackupSafe";Value = $true},
            [PSCustomObject]@{Key = "ViewAuditLog";Value = $true},
            [PSCustomObject]@{Key = "ViewSafeMembers";Value = $true},
            [PSCustomObject]@{Key = "RequestsAuthorizationLevel";Value = 0},
            [PSCustomObject]@{Key = "AccessWithoutConfirmation";Value = $false},
            [PSCustomObject]@{Key = "CreateFolders";Value = $true},
            [PSCustomObject]@{Key = "DeleteFolders";Value = $true},
            [PSCustomObject]@{Key = "MoveAccountsAndFolders";Value = $true}
    )
    if($groupname -eq ""){
        $json = [PSCustomObject]@{member = @{
            Permissions = $perm
        } } | ConvertTo-Json -Depth 4 -Compress
    }else{
        $json = [PSCustomObject]@{member = @{
            MemberName = "$groupname";
            SearchIn = "Vault";
            Permissions = $perm
        } } | ConvertTo-Json -Depth 4 -Compress
    }
    
    return $json
}
function GetVaultAdminPermissionsJSON{
    param($groupname) 
    $json = [PSCustomObject]@{member = @{
        MemberName = "$groupname";
        SearchIn = "Vault";
        Permissions = @(
            [PSCustomObject]@{Key = "UseAccounts";Value = $true},
            [PSCustomObject]@{Key = "RetrieveAccounts";Value = $true},
            [PSCustomObject]@{Key = "ListAccounts";Value = $true},
            [PSCustomObject]@{Key = "AddAccounts";Value = $true},
            [PSCustomObject]@{Key = "UpdateAccountContent";Value = $true},
            [PSCustomObject]@{Key = "UpdateAccountProperties";Value = $true},
            [PSCustomObject]@{Key = "InitiateCPMAccountManagementOperations";Value = $true},
            [PSCustomObject]@{Key = "SpecifyNextAccountContent";Value = $true},
            [PSCustomObject]@{Key = "RenameAccounts";Value = $true},
            [PSCustomObject]@{Key = "DeleteAccounts";Value = $true},
            [PSCustomObject]@{Key = "UnlockAccounts";Value = $true},
            [PSCustomObject]@{Key = "ManageSafe";Value = $true},
            [PSCustomObject]@{Key = "ManageSafeMembers";Value = $true},
            [PSCustomObject]@{Key = "BackupSafe";Value = $true},
            [PSCustomObject]@{Key = "ViewAuditLog";Value = $true},
            [PSCustomObject]@{Key = "ViewSafeMembers";Value = $true},
            [PSCustomObject]@{Key = "RequestsAuthorizationLevel";Value = 0},
            [PSCustomObject]@{Key = "AccessWithoutConfirmation";Value = $true},
            [PSCustomObject]@{Key = "CreateFolders";Value = $true},
            [PSCustomObject]@{Key = "DeleteFolders";Value = $true},
            [PSCustomObject]@{Key = "MoveAccountsAndFolders";Value = $true}
        )
    } } | ConvertTo-Json -Depth 4 -Compress
    return $json
}
function DisableSSL {
    
    try{
        if($DisableSSLVerify -eq $true){
            Write-Warning "It is not Recommended to disable SSL verification"
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        }
		
	} catch {
		LogError -message $Error[0] 
        Throw $Error[0] 
        return
    }
    
}
function Accept-AllSSL {
        add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3, [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12
}
function GetAuthorizationTokenHeader {
    param($token="")
    if($token -eq "") {
        $token = GetAuthorizationToken 
    }

    $result = @{
        'Authorization' = $token
    }

    return $result
}
function GetCredential {
    param($Usr="",$Pwd="")
    if($Usr -eq ""){
        $Usr = Read-Host "Enter Username"
    }
    if($Pwd -eq ""){
        $Pwd = Read-Host "Enter Password" -AsSecureString
    }
    $Bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Pwd)
    $PwdC = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($Bstr)
    $ret = [PSCustomObject]@{
        Username                    = $Usr
        Password                    = $PwdC
    }

    return $ret
}
function GetAuthorizationToken {
    param($Usr="",$Pwd="",$cyberarkLogonUrl="")
    if($Usr -eq ""){
        $Usr = Read-Host "Enter Username"
    }
    if($Pwd -eq ""){
        $Pwd = Read-Host "Enter Password" -AsSecureString
    }
    if($cyberarkLogonUrl.Length -gt 0){
        LogMessage -message "Override logon URL with '$cyberarkLogonUrl'"
        $LogonUri = $cyberarkLogonUrl
    }
    $Bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Pwd)
    $PwdC = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($Bstr)
   
    #region Call CyberArk for AuthZ token and create AuthZ header
    $LogonBody = @{ username = $Usr; password = $PwdC } | ConvertTo-Json -Compress


    
    $AuthZToken = ""
    try {
        DisableSSL
        If($DisableSSLVerify){
            #$AuthZToken = Invoke-RestMethod -Uri $LogonUri -Method Post -Body $LogonBody -ContentType "application/json" -SkipCertificateCheck
            $AuthZToken = Invoke-RestMethod -Uri $LogonUri -Method Post -Body $LogonBody -ContentType "application/json" # -SkipCertificateCheck
        }else{
            $AuthZToken = Invoke-RestMethod -Uri $LogonUri -Method Post -Body $LogonBody -ContentType "application/json" 
        }
       
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        Throw $Error[0] 
        return
    }


    return $AuthZToken
}
function Logoff {
    param($authZtoken,$BaseURL="") 
    
    if($BaseURL -ne ""){
        $LogoffUri = $BaseURL+'/API/Auth/Logoff'
    }
    try {
        DisableSSL
        if($DisableSSLVerify){
            $logoffresult = Invoke-RestMethod -Uri $LogoffUri -Method Post -Headers $authZtoken -ContentType  "application/json" -SkipCertificateCheck
        }else{
            $logoffresult = Invoke-RestMethod -Uri $LogoffUri -Method Post -Headers $authZtoken -ContentType  "application/json"
        }
        
     }
     catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
         LogError -message $Error[0] 
         Throw $Error[0] 
         return
     }


}
function FindCyberArkGroup {
    param($searchString,$authZtoken) 
    $FindURI = $FindGroupURI -f $searchString
    
    $result = $null

    try {
       $result = Invoke-RestMethod -Uri $FindURI -Method Get -Headers $authZtoken -ContentType "application/json"
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        Throw $Error[0] 
        return
    }

    return $result
}

function CreateCyberArkSafe {
    param($body,$authZtoken,$url="") 
    $result = $null
    if($null -ne $url -and $url -ne ""){
        LogMessage -message "Override Create Safe URL with '$url'"
        $CreateCyberArkSafeURI2 = $url
    }
    try {
       $result = Invoke-RestMethod -Uri $CreateCyberArkSafeURI2 -Method Post -Body $body -Headers $AuthZHeader -ContentType "application/json"
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        Throw $Error[0] 
        return
    }


    return $result

}

function CreateCyberArkGroup {
    param($body,$authZtoken) 
    

    $result = $null

    try {
       $result = Invoke-RestMethod -Uri $AddGroupURI -Method Post -Body $AddGroupBody -Headers $AuthZHeader -ContentType "application/json"
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        Throw $Error[0] 
        return
    }


    return $result
}
function UpdateCyberArkSafe {
    param($body,$authZtoken,$updateURI) 
    $result = $null
    
    try {
       $result = Invoke-RestMethod -Uri $updateURI -Method Put -Body $body -Headers $AuthZHeader -ContentType "application/json"
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        Throw $Error[0] 
        return
    }


    return $result

}
function UpdateCyberArkGroup {
    param($body,$authZtoken,$id) 
    
    $updateURL = $UpdateGroupURI -f $id
    $result = $null

    try {
       $result = Invoke-RestMethod -Uri $updateURL -Method Put -Body $body -Headers $AuthZHeader -ContentType "application/json"
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        Throw $Error[0] 
        return
    }


    return $result
}
function FindSafe {
    param($safename,$authZtoken)
    $SearchURI = $SearchSafes -f $safename

    $result = $null


    try {
       $result = Invoke-RestMethod -Uri $SearchURI -Method Get -Headers $authZtoken -ContentType "application/json"
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        Throw $Error[0] 
        return
    }

    return $result
}
function GetSafeMembers {
    param($safename,$authZtoken)
    $result = $null
    $SearchForMembersURI = $SearchMembersURI -f $safename
    try {
       $result = Invoke-RestMethod -Uri $SearchForMembersURI -Method Get -Headers $authZtoken -ContentType "application/json"
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        Throw $Error[0] 
        return
    }

    return $result
}
function AddSafeMember {
    param($safename,$body,$authZtoken)

    $AddMemberUri = $AddSafeMemberURI -f $safename
    $result = $null
    try {
        
        $result = Invoke-RestMethod -Uri $AddMemberUri -Method Post -Body $body -Headers $authZtoken -ContentType "application/json"
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        Throw $Error[0] 
        return
    }
    return $result
}
function DeleteSafeMember {
    param($safename,$membername,$authZtoken)

    $DeleteMemberUri = $DeleteSafeMemberURI -f $safename, $membername
    $result = $null
    try {
        
        $result = Invoke-RestMethod -Uri $DeleteMemberUri -Method Delete -Headers $authZtoken -ContentType "application/json"
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        Throw $Error[0] 
        return
    }
    return $result
}
function UpdateSafeMemberPermissions {
    param($safename,$groupname,$body,$authZtoken)
    $result = $null
    $UpdateMemberURI = $UpdateSafeMemberURI -f $safename, $groupname

    try {
        $result = Invoke-RestMethod -Uri $UpdateMemberURI -Method Put -Body $body -Headers $authZtoken -ContentType "application/json"
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        Throw $Error[0] 
        return
    }
    return $result

}
function PACLI_OpenSafe {
    param($VaultName,$Username,$SourceSafeName)
    LogMessage -Message "Openning safe $SourceSafeName"

    try 
    {
        $result = & $PACLI_EXE OPENSAFE  VAULT= """$VaultName""" USER=$Username SAFE= """$SourceSafeName"""
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException]
    {
        LogError -message $Error[0] 
    }

    
    return $result
}
function PACLI_CloseSafe {
    param($VaultName,$Username,$SourceSafeName)
    LogMessage -Message "Closing safe $SourceSafeName"
    
    try 
    {
        $result = & $PACLI_EXE CLOSESAFE  VAULT= """$VaultName""" USER=$Username SAFE= """$SourceSafeName"""
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException]
    {
        LogError -message $Error[0] 
    }

    
    return $result
}
function PACLI_ConnectToVault(){
	PARAM($VaultName,$Username,$ParmFile,$LogonFile)
	END 
	{

        $CONNECTED = $false

		LogMessage -Message "Connecting..."
        
        try 
        {
            & $PACLI_EXE INIT
            & $PACLI_EXE DEFINEFROMFILE VAULT= """$VaultName""" PARMFILE= """$ParmFile"""
            $logonresult = & $PACLI_EXE LOGON VAULT= """$VaultName""" LOGONFILE= """$LogonFile""" USER=$Username
            LogMessage -message "Logon result: $logonresult"
            $result = & $PACLI_EXE USERDETAILS VAULT= """$VaultName""" USER=$Username DESTUSER= """$Username""" output("(all)")
        }
        catch [System.Net.WebException],[System.IO.IOException],[System.SystemException]
        {
            LogError -message $Error[0] 
        }
        
		if($result.Length -eq 0) {LogMessage -Message "Error logging in"}else{ 
            $CONNECTED = $true
			LogMessage -Message "Connected"  
		}
	}
}
function PACLI_DisconnectVault(){
	PARAM($VaultName,$Username)
	END 
	{
		LogMessage -Message "Disconnecting..." 
        try 
        {
            #$result = & $PACLI_EXE LOGOFF VAULT= """$VaultName""" USER="""$Username"""
            LogMessage -message "Logoff result: $result"
        } 
        catch [System.Net.WebException],[System.IO.IOException],[System.SystemException]
        {
            LogError -message $Error[0] 
        }
        

		& $PACLI_EXE TERM
        $CONNECTED = $false
		LogMessage -Message "Disconnected"
	}
}
function PACLI_GenerateFilesListReport{
    param($VaultName,$Username,$SourceSafeName,$SourceFolderName,$SafeFilesListReport,$FilesListOutputParam)

    try 
    {
        #$result = & $PACLI_EXE FILESLIST  VAULT= """$VaultName""" USER=$Username SAFE= """$SourceSafeName""" FOLDER= """$SourceFolderName""" output("(all)")
        
        
        $cmd = """$PACLI_EXE""" + " fileslist user=administrator vault=PrimaryVault safe=PasswordManager_Pending folder=root output(name)"
        
        $command = "cmd.exe /C ""$PACLI_EXE""" + " fileslist user=""administrator"" vault=""PrimaryVault"" safe=""PasswordManager_Pending"" folder=""root"" output(""(all)"")"


        #Write-Output $cmd

        #$result = & $cmd
        Invoke-Expression -Command:$command

        


        #output("(all)") #| Out-File $SafeFilesListReport -Append
        
        LogMessage -message "File List Result: $result"
    } 
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException]
    {
        LogError -message $Error[0] 
    }
    return $result

}
function PACLI_UpdateGroupDescription(){
    PARAM($VaultName,$UserName,$GroupName,$Description)
    END
    {
        $result = & $PACLI_EXE UPDATEGROUP VAULT= """$VaultName""" USER=$Username GROUP= """$GroupName""" DESCRIPTION= """$Description""" LOCATION= """\"""
        
    }
}

function PACLI_DeleteGroup(){
    PARAM($VaultName,$UserName,$GroupName)
    END
    {
        $result = & $PACLI_EXE DELETEGROUP VAULT= """$VaultName""" USER=$UserName GROUP= """$GroupName"""    

        return $result
    }
}

function AddMemberToGroup {
    param($authZtoken,$groupid,$memberid,$membertype)
    $result = $null
    $AddURL = $AddGroupMember -f $groupid
    $AddMemberBody = @{ memberId = $memberid; memberType = $membertype } | ConvertTo-Json -Compress


    <#
    Example post
    {

        "memberId": "string",
        "memberType": "Vault",
        "domainName": "string"
    }
    #>


    try {
        $result = Invoke-RestMethod -Uri $AddURL -Method Post -Body $AddMemberBody -Headers $authZtoken -ContentType "application/json"
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        Throw $Error[0] 
        return
    }
    return $result

}
function RemoveMemberFromGroup {
    param($authZtoken,$groupid,$membername)
    $result = $null
    $RemoveURL = $RemoveGroupMember -f $groupid,$membername 

    

    try {
        $result = Invoke-RestMethod -Uri $RemoveURL -Method Delete -Headers $authZtoken -ContentType "application/json"
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        #Throw $Error[0] 
        #return
    }
    return $result

}
function GetUser {
    param($authZtoken,$searchstring)
    $result = $null
    $FindUrl = $FindUser -f $searchstring


    try {
        $result = Invoke-RestMethod -Uri $FindUrl -Method Get -Headers $authZtoken -ContentType "application/json"
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        Throw $Error[0] 
        return
    }
    return $result
}
function POSHPACLI_GetGroupDetails {
    param($groupName)
    $result  =$null
    try {
        $result = Get-PVGroup -GroupName $groupName -ErrorAction Ignore
    }
    catch {
        LogMessage -message $Error[0] 
        return $null
    }
    return $result
}
function POSHPACLI_AddGroup {
    param($groupName,$description="",$location)
    $result  =$null
    try {
        if($description -eq ""){
            $result = New-PVGroup -GroupName $groupName -location $location
        }else{
            $result = New-PVGroup -GroupName $groupName -description $description -location $location
        }
        
        
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        Throw $Error[0] 
        return $null
    }
    $result = POSHPACLI_GetGroupDetails -groupName $groupName
    return $result
}
function POSHPACLI_UpdateGroup {
    param($groupName,$description,$location)
    $result  =$null
    try {
        $result = Set-PVGroup -GroupName $groupName -description $description -location $location
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        Throw $Error[0] 
        return $null
    }
    return $result
}
function POSHPACLI_DeleteGroup {
    param($groupName)
    $result  =$null
    try {
        $result = Remove-PVGroup -GroupName $groupName 
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        Throw $Error[0] 
        return $null
    }
    return $result
}
function PoSHPACLI_ConnectVault_Gateway {
    param($config)
    $connected = PoSHPACLI_ConnectVault -VaultName $config.vaultname `
        -Username $config.gwuser `
        -LogonFile $config.logonfile `
        -address $config.vaultip `
        -sessionid $config.sessionid `
        -pacliexe $config.pacliexe -autoChangePassword $true -password $null
    return $connected
}
function PoSHPACLI_ConnectVault {
    param($VaultName,$Username,$LogonFile,$address,$sessionid, $pacliexe,[bool]$autoChangePassword=$false,[securestring]$password)
    LogMessage -Message "Connection to vault using PoSHPACLI..." 
    $result = $false
    $fileexists = $false
    if($null -ne $LogonFile){
        $fileexists = Test-Path -Path $LogonFile
    }
    if($null -eq $password -or $password.Length -eq 0){
        LogMessage -Message "Password is null or empty!" 
    }
    if($fileexists -eq $false){
        LogMessage -Message "Logon file '$LogonFile' does not exist!" 
        
    }
    if($fileexists -eq $false -and $null -eq $password){
        LogMessage -Message "No password provided nor is there a logon file!" 
        return $result
    }
    try {

        Set-PVConfiguration -ClientPath $pacliexe
        Start-PVPacli -sessionID $sessionid
        New-PVVaultDefinition -vault $VaultName -address $address
        # $result = Connect-PVVault -user $Username -logonFile $LogonFile
        $result = $true
        
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
    }
    if($null -ne $password -and $password.Length -ne 0){
        $result = POSHPaCLI_LogonVault -user $Username -password $password -autoChangePassword $autoChangePassword 
        return $result
    }
    if($fileexists -eq $true){
        $result = POSHPaCLI_LogonVault -user $Username -logonFile $LogonFile -autoChangePassword $autoChangePassword 
        return $result
    }
    
    return $result
    
}
function POSHPaCLI_LogonVault {
    param(
        [Parameter(
			Mandatory = $True,
			ValueFromPipelineByPropertyName = $True)]
		[string]$user,

		[Parameter(
			Mandatory = $False,
			ValueFromPipelineByPropertyName = $True)]
		[securestring]$password,

		[Parameter(
			Mandatory = $False,
			ValueFromPipelineByPropertyName = $True)]
		[securestring]$newPassword,

		[Parameter(
			Mandatory = $False,
			ValueFromPipelineByPropertyName = $True)]
		[string]$logonFile,

		[Parameter(
			Mandatory = $False,
			ValueFromPipelineByPropertyName = $True)]
		[bool]$autoChangePassword,

		[Parameter(
			Mandatory = $False,
			ValueFromPipelineByPropertyName = $True)]
		[switch]$failIfConnected,

		[Parameter(
			Mandatory = $False,
			ValueFromPipelineByPropertyName = $True)]
		[switch]$radius
    )
    <#
    Logon options:
    0 = use logon file
    1 = use logon file with auto change password

    #>
    $result = $false

    if(($null -eq $logonFile -or $logonFile.Length -eq 0) -and $null -eq $password){
        $msg = "Password or logon file must be provided"
        LogError -message $msg
        return $false
        
    }
    $logonMethod = 0 # use logon file. For password, set to 1

    if($null -eq $logonFile -or $logonFile.Length -eq 0){
        $logonMethod  = 1 # use pwd
    }

    if($logonMethod -eq 1){
        $Bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
        $PwdC = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($Bstr)
    }
    $logonFileExists  =$false
    [int]$logonOptions = 0 
    if($null -ne $logonFile -and $logonFile.Length -gt 0){
        $logonFileExists = Test-Path -Path $logonFile -PathType Leaf
    }
    
    if($null -ne $logonFile -and $autoChangePassword -eq $false -and $logonFileExists -eq $true) {$logonOptions = 0}
    if($null -ne $logonFile -and $autoChangePassword -eq $true -and $logonFileExists -eq $true) {$logonOptions = 1}
    try {
        switch ($logonOptions){
            0 {

                switch ($logonMethod){
                    0 {
                        LogMessage "Logon to vault as $Username using logon file '$LogonFile'"
                        Connect-PVVault -user $Username -logonFile $LogonFile
                    }
                    1 {
                        LogMessage "Logon to vault as $Username using password"
                        Connect-PVVault -user $Username -password $password
                    }
                }


                
                $result = $true
                break
            }
            1 {

                switch ($logonMethod){
                    0 {
                        LogMessage "Logon to vault as $Username using logon file '$LogonFile'. Auto change PWD applied."
                        Connect-PVVault -user $Username -logonFile $LogonFile -autoChangePassword
                    }
                    1 {
                        LogMessage "Logon to vault as $Username using password"
                        Connect-PVVault -user $Username -password $password  -autoChangePassword
                    }
                }


                $result = $true
                break
            }
            default {
                LogMessage -message "Logon options could not be determined. Not enought information. Check parameters. ";
                $result = $false
                break
            }
        }
        
    } catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        $result = $false
    }

    return $result

}

function PoSHPACLI_DisconnectVault {
    LogMessage -Message "Disconnecting vault using PoSHPACLI..." 
    try {

        Disconnect-PVVault
        Stop-PVPacli   
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
    }
    #Stop-PVPacli
    return $result
    
}

function PoSHPACLI_FindFile {
    param($Pattern,$TargetSafeName,$TargetFolder,$Username,$LogonFile,$VaultName,$VaultIP,$SessionID,$PACLIEXE,[securestring]$password)
    $result = $null
    $connected = PoSHPACLI_ConnectVault -VaultName $VaultName `
        -Username $Username `
        -LogonFile $LogonFile `
        -address $VaultIP `
        -sessionid $SessionID `
        -pacliexe $PACLIEXE `
        -password $password
        
    if($connected -eq $false -or $null -eq $connected){
        LogError -message "Could not connect to vault!"
        return $result;
    }
    try {
        
        #PoSHPACLI_OpenSafe -SafeName $TargetSafeName
        
        $result = Find-PVFile -folder $TargetFolder `
            -safe $TargetSafeName `
            -filePattern $Pattern -deletedOption WITHOUT_DELETED
        
        #PoSHPACLI_CloseSafe -SafeName $config.targetsafe
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
    }
    
    PoSHPACLI_DisconnectVault
    return $result
}
function PoSHPACLI_UpdateAccountsFeedFile {
    param($AccountsFeedConfigPath,$Filename = "")
    $config = LoadAccountsFeedConfig -configpath $AccountsFeedConfigPath
    $connected = PoSHPACLI_ConnectVault -VaultName $config.vaultname `
        -Username $config.user `
        -LogonFile $config.logonfile `
        -address $config.vaultip `
        -sessionid $config.sessionid `
        -pacliexe $config.pacliexe

    if($connected -eq $false -or $null -eq $connected){
        LogError -message "Could not connect to vault!"
        return $result;
    }
    
    try {
        $sourcepath_folder = Split-Path $config.sourcepath 
        $sourcepath_filename = Split-Path $config.sourcepath -leaf
        PoSHPACLI_OpenSafe -SafeName $config.targetsafe
        if($Filename -eq ""){$Filename = $sourcepath_filename}
        Add-PVFile -folder $config.targetfolder `
            -safe $config.targetsafe `
            -file $Filename `
            -localFolder $sourcepath_folder `
            -localFile $sourcepath_filename
        
        PoSHPACLI_CloseSafe -SafeName $config.targetsafe
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
    }
    
    PoSHPACLI_DisconnectVault
}
function PoSHPACLI_UploadFile {
    param($inputpath,$TargetSafe,$TargetFolder,$VaultName,$Usr,$LogonFile,[securestring]$Password,$VaultAddress,$sessionid,$PACLI_EXE)
    $connected = $null
    $result = $null
    if($null -ne $LogonFile -and $LogonFile.Length -gt 0){
        $connected = PoSHPACLI_ConnectVault -VaultName $VaultName `
            -Username $Usr `
            -LogonFile $LogonFile `
            -address $VaultAddress `
            -sessionid $sessionid `
            -pacliexe $PACLI_EXE
    }else {
        $connected = PoSHPACLI_ConnectVault -VaultName $VaultName `
            -Username $Usr `
            -Password $Password `
            -address $VaultAddress `
            -sessionid $sessionid `
            -pacliexe $PACLI_EXE
    }
    if($connected -eq $false -or $null -eq $connected){
        LogError -message "Could not connect to vault!"
        return $result;
    }
    
    $uploadPath = (Get-ChildItem -Path $inputpath).FullName
    PoSHPACLI_OpenSafe -SafeName $TargetSafe
    
    try {
        $sourcepath_folder = Split-Path $uploadPath 
        $sourcepath_filename = Split-Path $uploadPath -leaf
        
        $result = Add-PVFile -folder $TargetFolder `
            -safe $TargetSafe `
            -file $sourcepath_filename `
            -localFolder $sourcepath_folder `
            -localFile $sourcepath_filename
        
        # if($null -eq $result){
        #     LogError -message "File not uploaded!"
        # }
        #PoSHPACLI_CloseSafe -SafeName $config.targetsafe
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
    }
    
    PoSHPACLI_DisconnectVault
}

function ImportCSV {
    param($inputfilepath)
    $ret  =$null
    try {
        $ret = Import-Csv -Path $inputfilepath 
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
    }
    return $ret
}
function LoadAccountsFeedConfig {
    param($configpath)

    $ConfigDataJSON = LoadJSONConfig -configpath $configpath
    
    return $ConfigDataJSON 

}
function LoadJSONConfig {
    param($configpath)

    $ConfigDataJSON = $null
    try {

        $ConfigData                                = Get-Content -Path $configpath #| ConvertTo-Json
        $ConfigDataJSON                            = $ConfigData | ConvertFrom-Json 
        
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
    }
    return $ConfigDataJSON 
}
function PoSHPACLI_GetPassword_Gateway {
    param($config,$reason,$user,$script)
    $connected = PoSHPACLI_ConnectVault_Gateway -config $config
    $passwordObject = $null
    if($null -eq $reason -or $reason -eq ""){
        $reason = "Executing $script as user $user"
    }
    if($connected -eq $false) {return $null}
    try {
       
        PoSHPACLI_OpenSafe -SafeName $config.gwusersafe
        
        $passwordObject = Get-PVPasswordObject -safe $config.gwusersafe -folder $config.gwuserfolder -file $config.gwuserobjectname -requestReason $reason
        
        
        
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
    }
    PoSHPACLI_CloseSafe -SafeName $config.gwusersafe
    PoSHPACLI_DisconnectVault

    return $passwordObject

    
}
function PoSHPACLI_GetPassword {
    param($vaultname,$user,$logonfile,$sessionid,$vaultip,$pacliexe,$targetsafe,$folder,$objectname,$reason,$autoChangePassword=$false,[securestring]$password)

    $passwordObject = $null

    $connected = PoSHPACLI_ConnectVault -VaultName $vaultname `
        -Username $user `
        -LogonFile $logonfile `
        -address $vaultip `
        -sessionid $sessionid `
        -pacliexe $pacliexe -autoChangePassword $autoChangePassword -password $password

    if($connected -eq $false) {return $null}
    try {
       
        PoSHPACLI_OpenSafe -SafeName $targetsafe
        
        $passwordObject = Get-PVPasswordObject -safe $targetsafe -folder $folder -file $objectname -requestReason $reason
        
        
        
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
    }
    PoSHPACLI_CloseSafe -SafeName $targetsafe
    PoSHPACLI_DisconnectVault

    return $passwordObject

}
function PoSHPACLI_GetFileListReport {
    param($SafeName,$Folder,$OutputPath="")
    $ret = $null 
    PoSHPACLI_OpenSafe -SafeName $SafeName
    $ret = POSHPaCLI_GetFileListData -safe $SafeName -folder $Folder
    if($OutputPath -eq ""){
        $ret | Select Filename 
    }else{
        $ret | Select Filename | Export-Csv -Path $OutputPath
    }
    
    PoSHPACLI_CloseSafe -SafeName $SafeName 



    # try {
    #     $ret = POSHPaCLI_GetFileListData -safe $SafeName -folder $Folder
    # }
    # catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
    #     LogError -message $Error[0] 
    #     return $ret
    # }
    # PoSHPACLI_CloseSafe -SafeName $SafeName
    return $ret
}
function POSHPaCLI_GetFileListData {
    param($SafeName,$Folder)
    $ret = $null 
    try {
        $ret = Get-PVFileList -safe $SafeName -folder $Folder
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
    }
    return $ret
}
function PoSHPACLI_GetFileCategory {
    param($FileName,$SafeName,$Folder)
    $ret = $null 
    try {
       
        $ret = Get-PVFileCategory -file $FileName -safe $SafeName -folder $Folder
        
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
    }

    return $ret

}
function POSHPaCLI_ExportFile {
    param($FileName,$SafeName,$Folder,$localFolder,$localFile)
    
    $result = $false
    $fullPath = Join-Path -Path $localFolder -ChildPath $localFile
    
    if($localFolder -eq "" -or $localFolder -eq ""){
        LogMessage -message "Local path is blank."
        return
    }

    $folderexists = Test-Path -Path $localFolder -PathType Container
    if($folderexists -eq $false) {
        LogMessage -message "Folder does not exist"
        return
    }
    try {
        
        $fileexists = Test-Path -Path $fullPath 
        if($fileexists -eq $true) {Remove-Item $fullPath}
        $fileexists = $false
        Get-PVFile -file $FileName -safe $SafeName -folder $Folder -localFolder $localFolder -localFile $localFile
        $fileexists = Test-Path -Path $fullPath
        $result = $fileexists
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
    }

    return $result
}
function PoSHPACLI_DeleteFile {
    param($filename,$localFolder,$vaultname,$user,$logonfile,$sessionid,$vaultip,$pacliexe,$targetsafe,$folder,$objectname,$reason,$autoChangePassword=$false,[securestring]$password,$deleteFromSafe=$false)
    
    LogMessage -message "Attempting to delete file '$filename' from safe '$targetsafe'"

    $results = PoshPACLI_FindFile -Pattern $filename `
        -TargetSafeName $targetsafe `
        -TargetFolder $folder `
        -Username $user `
        -LogonFile $logonfile `
        -VaultName $vaultname `
        -VaultIP $vaultip `
        -SessionID $sessionid `
        -PACLIEXE $pacliexe `
        -password $password


    $connected = PoSHPACLI_ConnectVault -VaultName $vaultname `
        -Username $user `
        -LogonFile $logonfile `
        -address $vaultip `
        -sessionid $sessionid `
        -pacliexe $pacliexe -autoChangePassword $autoChangePassword -password $password

    if($connected){
        if($null -ne $results){
            $removeFile = $false
            if($null -ne $deleteFromSafe -and $deleteFromSafe -ne ""){
                $removeFile = $deleteFromSafe -eq "Yes"
            }
            try {
                Remove-PVFile -safe $targetsafe -folder $folder -file $filename
            }
            catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] 
            {
                LogError -message $Error[0] 
            }
        }else{
            LogError -message "File '$filename' does not exist in safe $targetsafe"
        }
        PoSHPACLI_DisconnectVault
    }
}
function PoSHPACLI_GetFile {
    param($filename,$localFolder,$vaultname,$user,$logonfile,$sessionid,$vaultip,$pacliexe,$targetsafe,$folder,$objectname,$reason,$autoChangePassword=$false,[securestring]$password,$deleteFromSafe=$false)

    $result = $false
    
    $connected = PoSHPACLI_ConnectVault -VaultName $vaultname `
        -Username $user `
        -LogonFile $logonfile `
        -address $vaultip `
        -sessionid $sessionid `
        -pacliexe $pacliexe -autoChangePassword $autoChangePassword -password $password

    if($connected -eq $false) {return $null}
    try {
        
        PoSHPACLI_OpenSafe -SafeName $targetsafe
        $fileExists = $false
        $retrievedFile = Join-Path $localFolder -ChildPath $filename
        $fileExists = Test-Path $retrievedFile 
        if($fileExists){
            LogMessage -message "File '$retrievedFile' exists. Deleting file."
            Remove-Item -Path $retrievedFile 
        }
        LogMessage -message "Getting file '$filename' from vault, safe $targetsafe"
        #Get-PVFile -safe $targetsafe -folder $folder -file $filename -localFolder $localFolder -requestReason $reason -localFile $filename
        Get-PVFile -safe $targetsafe -folder $folder -file $filename -localFolder $localFolder -localFile $filename
        
        
        $fileExists = Test-Path $retrievedFile 
        if($fileExists){
            LogMessage -message "Retrieved file '$filename' and verified file exists. "

            if($deleteFromSafe){
                Remove-PVFile -safe $targetsafe -folder $folder -file $filename
            }
            
        }else{
            LogError -message "File '$retrievedFile' was not downloaded!"
        }
        
    
        $result = $true
        
        
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        $result = $false
    }
    PoSHPACLI_CloseSafe -SafeName $targetsafe
    PoSHPACLI_DisconnectVault

    return $result

}
function PoSHPACLI_GetFileCategoryValue {
    param($FileCategoryName,$FileCategoryObject)
    $ret = ""
    try {
       
        $ret_obj = ($FileCategoryObject | Where CategoryName -EQ $FileCategoryName | Select CategoryValue)
        if($ret_obj -eq $null){ LogMessage "File category $FileCategoryName is null"}
        else {
            $ret = $ret_obj.CategoryValue
        }
        
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
    }

    return $ret

}
function PoSHPACLI_OpenSafe {
    param($SafeName)
    $result = $false
    try {
        LogMessage -message "Open safe $SafeName"
        Open-PVSafe -safe $SafeName
        $result = $true
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
    }
    return $result
}
function PoSHPACLI_CloseSafe {
    param($SafeName)
    try {
        LogMessage -message "Close safe $SafeName"
        Close-PVSafe -safe $SafeName
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
    }
}
function PoSHPACLI_DeleteObject {
    param($SafeName,$Folder,$ObjectName="",$Username="",$Address="")
    try {
        LogMessage -message "Deleting object '$ObjectName' from Safe '$SafeName'"
        
        Remove-PVFile -safe $SafeName -file $ObjectName -folder $Folder
        
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
    }
}

function SearchFileList(){
    param($SourceFileList,$SafeName="",$Folder="",$Username="",$Address="",[Switch]$ExactMatch=$false)
    $ret = $null
    if($SafeName -eq "" -and $Folder -eq "" -and $Username -eq "" -and $Address -eq ""){
        LogMessage "No values to search. Returning null."
        return $ret
    }
    $cnt = 0
    try {
        $filelist = Import-Csv -Path $SourceFileList  
        if($ExactMatch){
            $ret = $filelist | Where-Object {$_.Username -eq $Username -and $_.Address -eq $Address -and $_.Safe -eq $SafeName -and $_.Folder -eq $Folder}
            if($ret -ne $null -and $ret.Count -eq 1){
                $cnt = 1
                return $ret
            }
            
        }else{
            $ret = $filelist | Where-Object {$_.Username -like $Username -and $_.Address -like $Address -and $_.Safe -like $SafeName -and $_.Folder -like $Folder}
            if($ret -ne $null){
                $cnt = $ret.Count
            }
            return $ret
        }
        
        
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
    }
    return $ret
}
function CreateFileListReport {
    param($outputpath)
    $OutputFileExists = Test-Path $outputpath
    try {
        if($OutputFileExists){
            Remove-Item $outputpath 
        }
        $FileListOutputHeader | Out-file -FilePath $outputpath
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
    }
}
function POSHPACLI_WriteFileCategories {
    param($SafeName,$Folder,$OutputFile)
    
    $RowNum = 0
    


    $data = $null
    try {
        $data = Find-PVFile -safe $SafeName -folder $Folder -includeFileCategories -Verbose -fileCategoriesSeparator "|" -fileCategoryValuesSeparator ","
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
    }
    if($data -eq $null) {return $false}

    $CountOfRows = $data.Count

    $data | ForEach-Object {
        
        $Filename = $_.Filename
        $UserName = ""
        $Address = ""
        $AccountDiscoveryDate = ""
        $AccountEnabled = ""
        $AccountOSGroups = ""
        $DiscoveryPlatformType = ""
        $LastPasswordSetDate = ""
        $LastLogonDate = ""
        $PasswordNeverExpires = ""
        $AccountExpirationDate = ""
        $OSVersion = ""
        $AccountCategory = ""
        $MachineOSFamily = ""
        $AccountType = ""
        $CreationMethod = ""
        $Dependencies = ""
        $DeviceType = ""

        $Domain = ""
        $UserDisplayName = ""
        $OU = ""
        $SID = ""


        $UID = ""
        $GID = ""

        $Fingerprint = ""
        $Length = ""
        $Path = ""
        $Format = ""
        $Comment = ""
        $Encryption = ""
        $PlatformId = ""
        $IP = ""
        if($FileName -eq $null){
            LogMessage -message "Filename is null"
        }else{
            
            $Ext = $FileName.substring($FileName.length-4,4).ToUpper()
    
            $FileCategories = $_.filecategories
            $Categories = $FileCategories.split("|")
            $Categories | ForEach-Object {
                $Category = $_ -split(",")
                switch ($Category[0]){
                    "UserName" {
                        $UserName = $Category[1]
                        break
                    }
                    "Address" {
                        $Address = $Category[1]
                        
                        break
                    }
                    "AccountDiscoveryDate" {
                        $AccountDiscoveryDate = $Category[1]
                        
                        break
                    }
                    "AccountEnabled" {
                        $UseAccountEnabledrName = $Category[1]
                        
                        break
                    }
                    "AccountOSGroups" {
                        $AccountOSGroups = $Category[1]
                        
                        break
                    }
                    "DiscoveryPlatformType" {
                        $DiscoveryPlatformType = $Category[1]
                        
                        break
                    }
                    "LastPasswordSetDate" {
                        $LastPasswordSetDate = $Category[1]
                        
                        break
                    }
                    "LastLogonDate" {
                        $LastLogonDate = $Category[1]
                        
                        break
                    }
                    "PasswordNeverExpires" {
                        $PasswordNeverExpires = $Category[1]
                        
                        break
                    }
                    "AccountExpirationDate" {
                        $AccountExpirationDate = $Category[1]
                        
                        break
                    }
                    "OSVersion" {
                        $OSVersion = $Category[1]
                        
                        break
                    }
                    "AccountCategory" {
                        $AccountCategory = $Category[1]
                        
                        break
                    }
                    "MachineOSFamily" {
                        $MachineOSFamily = $Category[1]
                        
                        break
                    }
                    "AccountType" {
                        $AccountType = $Category[1]
                        break
                    }
                    "CreationMethod" {
                        $CreationMethod = $Category[1]
                        break
                    }
                    "Dependencies" {
                        $Dependencies = $Category[1]
                        break
                    }
                    "DeviceType" {
                        $DeviceType = $Category[1]
                        break
                    }
                    "Domain" {
                        $Domain = $Category[1]
                        break
                    }
                    "UserDisplayName" {
                        $UserDisplayName = $Category[1]
                        break
                    }
                    "OU" {
                        $OU = $Category[1]
                        break
                    }
                    "SID" {
                        $SID = $Category[1]
                        break
                    }
                    "UID" {
                        $UID = $Category[1]
                        break
                    }
                    "GID" {
                        $GID = $Category[1]
                        break
                    }
                    "Fingerprint" {
                        $Fingerprint = $Category[1]
                        break
                    }
                    "Length" {
                        $Length = $Category[1]
                        break
                    }
                    "Path" {
                        $Path = $Category[1]
                        break
                    }
                    "Format" {
                        $Format = $Category[1]
                        break
                    }
                    "Comment" {
                        $Comment = $Category[1]
                        break
                    }
                    "Encryption" {
                        $Encryption = $Category[1]
                        break
                    }
                    "PolicyId" {
                        $PolicyId = $Category[1]
                        break
                    }
                    "IP" {
                        $IP = $Category[1]
                        break
                    }

                    default {
                        LogMessage -message "File category not found";
                        break
                    }
                }
            
            }
            $Output = $FileListOutputFormat -f $UserName,$Address,$AccountDiscoveryDate,$AccountEnabled,$AccountOSGroups,$DiscoveryPlatformType,$LastPasswordSetDate,$LastLogonDate,$PasswordNeverExpires,$AccountExpirationDate,$OSVersion,$AccountCategory,$MachineOSFamily,$AccountType,$CreationMethod,$Dependencies,$Domain,$UserDisplayName,$OU,$SID,$UID,$GID,$Fingerprint,$Length,$Path,$Format,$Comment,$Encryption,$DeviceType,$SafeName,$Folder,$FileName,"",$PolicyId,$IP
            $Output | Out-file -FilePath $OutputFile -Append
            $PercComplete = [math]::Round(($RowNum / $CountOfRows) * 100)
            Write-Progress -Activity "$RowNum objects scanned of $CountOfRows objects." -Status "$PercComplete% Complete:" -PercentComplete $PercComplete    
        }
       
    }

    Write-Verbose "$CountOfRows rows written to '$OutputFile'"
    return $true
}
function PoSHPACLI_WriteFileCategoryData {
    param($FileObject,$SafeName,$Folder,$Outputpath)
    $FileName = $FileObject.FileName
    if($FileName -eq $null){
        LogMessage -message "Filename is null"
    }else{
        $Ext = $FileName.substring($FileName.length-4,4).ToUpper()
        $UserName = ""
        $Address = ""
        $AccountDiscoveryDate = ""
        $AccountEnabled = ""
        $AccountOSGroups = ""
        $DiscoveryPlatformType = ""
        $LastPasswordSetDate = ""
        $LastLogonDate = ""
        $PasswordNeverExpires = ""
        $AccountExpirationDate = ""
        $OSVersion = ""
        $AccountCategory = ""
        $MachineOSFamily = ""
        $AccountType = ""
        $CreationMethod = ""
        $Dependencies = ""
        $DeviceType = ""

        $Domain = ""
        $UserDisplayName = ""
        $OU = ""
        $SID = ""


        $UID = ""
        $GID = ""

        $Fingerprint = ""
        $Length = ""
        $Path = ""
        $Format = ""
        $Comment = ""
        $Encryption = ""
        $PlatformId = ""
        $IP = ""

        if($Ext -ne ".TXT"){
            $FC_All = PoSHPACLI_GetFileCategory -FileName $FileName -SafeName $SafeName -Folder $Folder
            $UserName = PoSHPACLI_GetFileCategoryValue -FileCategoryName "UserName" -FileCategoryObject $FC_All
            $Address = PoSHPACLI_GetFileCategoryValue -FileCategoryName "Address" -FileCategoryObject $FC_All
            $AccountDiscoveryDate = PoSHPACLI_GetFileCategoryValue -FileCategoryName "AccountDiscoveryDate" -FileCategoryObject $FC_All
            $AccountEnabled = PoSHPACLI_GetFileCategoryValue -FileCategoryName "AccountEnabled" -FileCategoryObject $FC_All
            $AccountEnabled = PoSHPACLI_GetFileCategoryValue -FileCategoryName $AccountEnabled.ToLower()
            $AccountOSGroups = PoSHPACLI_GetFileCategoryValue -FileCategoryName "AccountOSGroups" -FileCategoryObject $FC_All
            $DiscoveryPlatformType = PoSHPACLI_GetFileCategoryValue -FileCategoryName "DiscoveryPlatformType" -FileCategoryObject $FC_All
            $LastPasswordSetDate = PoSHPACLI_GetFileCategoryValue -FileCategoryName "LastPasswordSetDate" -FileCategoryObject $FC_All
            $LastLogonDate = PoSHPACLI_GetFileCategoryValue -FileCategoryName "LastLogonDate" -FileCategoryObject $FC_All
            $PasswordNeverExpires = PoSHPACLI_GetFileCategoryValue -FileCategoryName "PasswordNeverExpires" -FileCategoryObject $FC_All
            $PasswordNeverExpires = PoSHPACLI_GetFileCategoryValue -FileCategoryName $PasswordNeverExpires.ToLower()
            $AccountExpirationDate = PoSHPACLI_GetFileCategoryValue -FileCategoryName "AccountExpirationDate" -FileCategoryObject $FC_All
            $OSVersion = PoSHPACLI_GetFileCategoryValue -FileCategoryName "OSVersion" -FileCategoryObject $FC_All
            $AccountCategory = PoSHPACLI_GetFileCategoryValue -FileCategoryName "AccountCategory" -FileCategoryObject $FC_All
            $AccountCategory = PoSHPACLI_GetFileCategoryValue -FileCategoryName $AccountCategory.ToLower()
            $MachineOSFamily = PoSHPACLI_GetFileCategoryValue -FileCategoryName "MachineOSFamily" -FileCategoryObject $FC_All
            $AccountType = PoSHPACLI_GetFileCategoryValue -FileCategoryName "AccountType" -FileCategoryObject $FC_All
            $CreationMethod = PoSHPACLI_GetFileCategoryValue -FileCategoryName "CreationMethod" -FileCategoryObject $FC_All
            $Dependencies = PoSHPACLI_GetFileCategoryValue -FileCategoryName "Dependencies" -FileCategoryObject $FC_All
            $PlatformId = PoSHPACLI_GetFileCategoryValue -FileCategoryName "PolicyId" -FileCategoryObject $FC_All
            $IP = PoSHPACLI_GetFileCategoryValue -FileCategoryName "IP" -FileCategoryObject $FC_All
            $DeviceType = PoSHPACLI_GetFileCategoryValue -FileCategoryName "DeviceType" -FileCategoryObject $FC_All

            if($DiscoveryPlatformType -eq "Windows Server Local" -or $DiscoveryPlatformType -eq "Windows Domain"){
                $Domain = PoSHPACLI_GetFileCategoryValue -FileCategoryName "Domain" -FileCategoryObject $FC_All
                $UserDisplayName = PoSHPACLI_GetFileCategoryValue -FileCategoryName "UserDisplayName" -FileCategoryObject $FC_All
                $OU = PoSHPACLI_GetFileCategoryValue -FileCategoryName "OU" -FileCategoryObject $FC_All
                $SID = PoSHPACLI_GetFileCategoryValue -FileCategoryName "SID" -FileCategoryObject $FC_All
                #$DeviceType = "Operating System"
            }
            if($DiscoveryPlatformType -eq "Unix" -or $DiscoveryPlatformType -eq "Unix SSH Key"){
                $UID = PoSHPACLI_GetFileCategoryValue -FileCategoryName "UID" -FileCategoryObject $FC_All
                $GID = PoSHPACLI_GetFileCategoryValue -FileCategoryName "GID" -FileCategoryObject $FC_All
                #$DeviceType = "Operating System"
            }
            if($DiscoveryPlatformType -eq "Unix SSH Key"){
                $Fingerprint = PoSHPACLI_GetFileCategoryValue -FileCategoryName "Fingerprint" -FileCategoryObject $FC_All
                $Length = PoSHPACLI_GetFileCategoryValue -FileCategoryName "Length" -FileCategoryObject $FC_All
                $Path = PoSHPACLI_GetFileCategoryValue -FileCategoryName "Path" -FileCategoryObject $FC_All
                $Format = PoSHPACLI_GetFileCategoryValue -FileCategoryName "Format" -FileCategoryObject $FC_All
                $Comment = PoSHPACLI_GetFileCategoryValue -FileCategoryName "Comment" -FileCategoryObject $FC_All
                $Encryption = PoSHPACLI_GetFileCategoryValue -FileCategoryName "Encryption" -FileCategoryObject $FC_All
                #$DeviceType = "Operating System"
            }
            
            $Output = $FileListOutputFormat -f $UserName,$Address,$AccountDiscoveryDate,$AccountEnabled,$AccountOSGroups,$DiscoveryPlatformType,$LastPasswordSetDate,$LastLogonDate,$PasswordNeverExpires,$AccountExpirationDate,$OSVersion,$AccountCategory,$MachineOSFamily,$AccountType,$CreationMethod,$Dependencies,$Domain,$UserDisplayName,$OU,$SID,$UID,$GID,$Fingerprint,$Length,$Path,$Format,$Comment,$Encryption,$DeviceType,$SafeName,$Folder,$FileName,"",$PlatformId,$IP
            $Output | Out-file -FilePath $outputpath -Append

        }
    }
}
function REST_Logon {
    param ($Usr,$PwdC,$AuthZURI,$AuthZGrantType)
    $result = $null 

    if($AuthZGrantType -eq "basic") {$result = REST_Authenticate_Basic -AuthZURI $AuthZURI -Usr $Usr -PwdC $PwdC}
    if($AuthZGrantType -eq "Bearer") {$result = REST_Authenticate_Bearer -AuthZURI $AuthZURI -Usr $Usr -PwdC $PwdC}

    return $result

}
function REST_Authenticate {
    param ($AuthZURI,$AuthNBody,$AuthNHeader=$null,$AuthNContentType)
    LogMessage -message "REST logon with content type: $AuthNContentType"
    try {
        $result = Invoke-RestMethod -Uri $AuthZURI -Method Post -Body $AuthNBody -ContentType $AuthNContentType -Headers $AuthNHeader
        
        #$token = $result.token
    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        Throw $Error[0] 
    }
    return $result
}
function REST_Authenticate_Basic {
    param ($Usr,$PwdC,$AuthZURI)
    
    $AuthNContentType = "application/json"
    $result = $null
    $token = ""
    $AuthNBody = @{
        username = "$Usr";
        password = "$PwdC";
        clientContext = 1;
        } | ConvertTo-Json -Compress 

    $result = REST_Authenticate -AuthZURI $AuthZURI -AuthNBody $AuthNBody -AuthNContentType "application/json"
    if($null -ne $result){
        $token = 'Bearer ' + $result.token
    }
    return $token
}
function REST_Authenticate_Bearer {
    param ($Usr,$PwdC,$AuthZURI)
    
    $result = $null
    $token = ""
    $AuthNContentType = "application/x-www-form-urlencoded"
    $AuthNHeader = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $AuthNHeader.Add("Content-Type", $AuthNContentType)
    $AuthNBody = "grant_type=password&username=$Usr&password=$PwdC"
    $result = REST_Authenticate -AuthZURI $AuthZURI -AuthNBody $AuthNBody -AuthNHeader $AuthNHeader -AuthNContentType $AuthNContentType

    
    if($null -ne $result){
        $resultJSON = $result | ConvertTo-Json 
        
        
        $token = 'Bearer ' + $result.access_token
        
    }
    return $token

    # $response = Invoke-RestMethod 'http://localhost:3097/Token' -Method 'POST' -Headers $headers -Body $body
    # $response | ConvertTo-Json
}
function GetPassword {
    param($authZtoken,$Id,$Reason)
    $result = $null
    $GetPassword = $GetPasswordURI -f $Id

    $GetPasswordBody = @{ reason = $Reason } | ConvertTo-Json -Compress

    <#
    Example of body: 
    
    {
        reason:"Testing",
        TicketingSystemName: "<Ticketing system>",
        TicketId: "<Ticketid>",
        Version: <version number>,
        ActionType: "<action type - show\copy\connect>isUse: <true\false>,
        Machine: "<my remote machine address>"
    }

    #>


    try {
        DisableSSL
        If($DisableSSLVerify){
            $result = Invoke-RestMethod -Uri $GetPassword -Method Post -Body $GetPasswordBody -Headers $authZtoken -ContentType "application/json" -SkipCertificateCheck
        }else{
            $result = Invoke-RestMethod -Uri $GetPassword -Method Post -Body $GetPasswordBody -Headers $authZtoken -ContentType "application/json" 
        }

    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        Throw $Error[0] 
        return
    }   
    return $result
}
function GetSafesList {
    param($authZtoken,$TargetSafe,$cyberarkGetSafesURL="")
    $result = $null
    $GetSafesListURI = ""
    if($cyberarkGetSafesURL.Length -gt 0){
        $GetSafesListURI = $cyberarkGetSafesURL
        LogMessage -message "Override Get Safes URL with '$GetSafesListURI'"
    }else{
        $GetSafesListURI = "$GetSafesAPIURI?search={0}"
        $GetSafesListURI = $GetSafesListURI -f $TargetSafe
    }
    
    try {
        DisableSSL
        If($DisableSSLVerify){
            $result = Invoke-RestMethod -Uri $GetSafesListURI -Method Get -Headers $authZtoken -ContentType "application/json" -SkipCertificateCheck
        }else{
            $result = Invoke-RestMethod -Uri $GetSafesListURI -Method Get -Headers $authZtoken -ContentType "application/json" 
        }

    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        #Throw $Error[0] 
        return
    }   
    return $result
}
function GetSafeDetails {
    param($authZtoken,$TargetSafe,$cyberarkGetSafesURL="",$extendedDetails="false",$includeAccounts="false")
    $result = $null
    $GetSafeDetailsURL = ""
    if($cyberarkGetSafesURL.Length -gt 0){
        $GetSafeDetailsURL = $cyberarkGetSafesURL
        LogMessage -message "Override Get Safes URL with '$GetSafeDetailsURL'"
    }else{
        $GetSafeDetailsURL = $GetSafeDetailsAPIURI
        $GetSafeDetailsURL = $GetSafeDetailsURL -f $TargetSafe,$extendedDetails,$includeAccounts
    }
    
    try {
        DisableSSL
        If($DisableSSLVerify){
            $result = Invoke-RestMethod -Uri $GetSafeDetailsURL -Method Get -Headers $authZtoken -ContentType "application/json" -SkipCertificateCheck
        }else{
            $result = Invoke-RestMethod -Uri $GetSafeDetailsURL -Method Get -Headers $authZtoken -ContentType "application/json" 
        }

    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        #Throw $Error[0] 
        return
    }   
    return $result
}
function GetAccounts {
    param($authZtoken,$TargetSafe,$cyberarkGetAccountsURL="")
    $result = $null
    if($cyberarkGetAccountsURL.Length -gt 0){
        LogMessage -message "Override Get Account URL with '$cyberarkGetAccountsURL'"
        $GetAccounts = $cyberarkGetAccountsURL
    }
    $GetAccounts = $GetAccountsURI -f $TargetSafe
    try {
        DisableSSL
        If($DisableSSLVerify){
            $result = Invoke-RestMethod -Uri $GetAccounts -Method Get -Headers $authZtoken -ContentType "application/json" -SkipCertificateCheck
        }else{
            $result = Invoke-RestMethod -Uri $GetAccounts -Method Get -Headers $authZtoken -ContentType "application/json" 
        }

    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        #Throw $Error[0] 
        return
    }   
    return $result
}
function GetPlatformDetails {
    param($authZtoken,$PlatformId)
    $result = $null
    $GetPlatforms = $GetPlatformDetailsURI -f $PlatformId
    try {
        DisableSSL
        $result = Invoke-RestMethod -Uri $GetPlatforms -Method Get -Headers $authZtoken -ContentType "application/json" 
        # If($DisableSSLVerify){
        #     $result = Invoke-RestMethod -Uri $GetPlatforms -Method Get -Headers $authZtoken -ContentType "application/json" -SkipCertificateCheck
        # }else{
        #     $result = Invoke-RestMethod -Uri $GetPlatforms -Method Get -Headers $authZtoken -ContentType "application/json" 
        # }

    }
    catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
        LogError -message $Error[0] 
        Throw $Error[0] 
        return
    }   
    return $result
}
function PoSHPACLI_SetPassword {
    param($password,$newPassword)
    $result = $false
    try {
        Set-PVUserPassword -password $password -newPassword $newPassword
        $result = $true
    } catch {
        LogError -message $Error[0] 
    }
    return $result
}
function CanCreateFile {
    param ($Path)
    $result = $true
    $fileexists = Test-Path -Path $logonFile
    if($fileexists -eq $false){
        try {
            New-Item -Path $Path
            Remove-Item -Path $Path
        } catch {
            LogError -message $Error[0] 
            $result = $false
        }
        
    }
    return $result
}
function PoSHPACLI_CreateCredFile {
    param ($logonFile,$username,$password)
    $result = $false
    $fileexists = Test-Path -Path $logonFile
    $cancreate = CanCreateFile -Path $logonFile
    if($cancreate -eq $false) {return $result}
    try {
        if($fileexists) {
            Remove-Item -Path $logonFile
            $fileexists = $false
        }
        New-PVLogonFile -logonFile $logonFile -username $username -password $password
        $fileexists = Test-Path -Path $logonFile
        $result = $fileexists
    } catch {
        LogError -message $Error[0] 
    }
    return $result
}
function PoSHPACLI_ChangePasswordInVaultOnly {
    param ($safe,$folder,$file,$password)
    $result = $false
    try {
        Add-PVPasswordObject -safe $safe -folder $folder -file $file -password $password
        $result = $true
    } catch {
        LogError -message $Error[0] 
    }
    return $result
}
function Show_Progress {
    param ($message="Processing...",$list=$null,$progressObject=$null)
    if($null -ne $progressObject){
        $progressObject.currentRow = $progressObject.currentRow + 1
    }else{
        if($null -ne $list){$progressObject = [pscustomobject]@{currentRow=1;totalRows=($list | Measure-Object).Count}}
    }
    if($null -ne $progressObject -and $progressObject.totalRows -gt 0 -and $progressObject.currentRow -lt ($progressObject.totalRows + 1)){
        # Write-Progress -Activity ("{0} of {1} items. {2}" -f $progressObject.currentRow,$progressObject.totalRows,$message) `
        #     -Status "$PercComplete% Complete:" -PercentComplete [math]::Round(($progressObject.currentRow / $progressObject.totalRows) * 100)

        
        $PercComplete = [math]::Round(($progressObject.currentRow / $progressObject.totalRows) * 100)
        Write-Progress -Activity ("{0} of {1} items. {2}" -f $progressObject.currentRow,$progressObject.totalRows,$message) `
            -Status "$PercComplete% Complete:" -PercentComplete ([math]::Round(($progressObject.currentRow / $progressObject.totalRows) * 100))
    }else{
        Write-Progress -Activity "$message" 
    }
    
    $progressObject
}
function Get-FilterExpression {
    param ($filters)
    $filtervalues = [System.Collections.ArrayList]@()
    $filters | Foreach-Object {
        $filterItem = $_
        switch ($_.operation) {
            "in"  {
                [void]$filtervalues.Add([scriptblock]::Create('$_.' + $filterItem.column + ' -' + $filterItem.operation + ' ("' + $filterItem.value + '" -split ",")'))
                break
            }
            "match" {
                
                if($null -ne $RegularExpressionFileFolder -and $RegularExpressionFileFolder -ne ""){
                    $matchTo = ""
                    $RegExFilePath = Join-Path -Path $RegularExpressionFileFolder -ChildPath $filterItem.value
                    if(Test-Path $RegExFilePath){
                        $matchTo = Get-Content $RegExFilePath
                        if($null -ne $matchTo -and $matchTo -ne ""){
                            [void]$filtervalues.Add([scriptblock]::Create('$_.' + $filterItem.column + ' -' + $filterItem.operation + ' "' + $matchTo + '"'))        
                        }else{
                            $filtersValid = $false
                        }
                    }else{
                        $filtersValid = $false
                    }
                }else{
                    $filtersValid = $false
                }
                
                
                break
            }
            "notmatch" {
                $matchTo = ""
                $RegExFilePath = Join-Path -Path $RegularExpressionFileFolder -ChildPath $filterItem.value
                if(Test-Path $RegExFilePath){
                    $matchTo = Get-Content $RegExFilePath
                    if($null -ne $matchTo -and $matchTo -ne ""){
                        [void]$filtervalues.Add([scriptblock]::Create('$_.' + $filterItem.column + ' -' + $filterItem.operation + ' "' + $matchTo + '"'))        
                    }else{
                        $filtersValid = $false
                    }
                }else{
                    $filtersValid = $false
                }
                
                break
            }
            default {
                [void]$filtervalues.Add([scriptblock]::Create('$_.' + $filterItem.column + ' -' + $filterItem.operation + ' "' + $filterItem.value + '"'))
                break
            }
        }
    }
    $filtervalues
}
