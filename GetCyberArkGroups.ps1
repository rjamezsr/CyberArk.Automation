#region About GetCyberArkGroups.ps1
###########################################################################
# This script reads group name from CSV file and outputs group data from CyberArk
#
# NOTES:
# 1. You will be prompted to provide a CyberArk login credential. It is highly recommended that the credential used to authenticate to the vault be protected in the vault.
# 2. If not verifying SSL, this script should be used for testing environment only and assumes that SSL verification can be bypassed. Please verify SSL certificate before using in production 

<#
SAMPLE INPUT CSV FILE....

GroupName          
-------------------
SampleGroupName1


SAMPLE OUTPUT CSV FILE...

GroupName                   Description                 Id              groupType	location	members
--------------------------- --------------------------- --------------- ----------  ---------   -----------     
SampleGroupName1            Some description            1               vault       //          jdoe,ssmith

###########################################################################
#>
#endregion
param (
    [Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,

    [Parameter(Mandatory=$true,HelpMessage="Please enter your CSV file location address (For example: c:\files\file1.csv")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[String]$path,

    
    [Parameter(Mandatory=$false)]
    # If exists, pass existing token
	[String]$authtoken,

    [Parameter(Mandatory=$false)]
	[String]$authtype, 
    
    [Parameter(Mandatory=$false)]
    [Switch]$DisableSSLVerify   
    
)





# . "C:\scripts\repo\cyberark.webapi.powershell\Scripts\Common.ps1"
. '.\Common.ps1'

$Executing = $MyInvocation.MyCommand.Name
LogMessage -message "********* Executing $Executing ***********"

#region Get list of groups from CSV
$Groups = Import-Csv -Path $path | Select Lob, Team, GroupName, RoleName
#endregion


#region Get authz header
$AuthZHeader = GetAuthorizationTokenHeader -token $authtoken
#endregion


$CyberArkGroups = [System.Collections.ArrayList]@()

<#
$myObject = [PSCustomObject]@{
    Name     = 'Kevin'
    Language = 'PowerShell'
    State    = 'Texas'
}

#>

#region Add groups to CyberArk
$Groups | ForEach-Object {
    $GroupName = $_.GroupName
    $Description = ""
    $Id = ""
    $members = ""
    $SearchString = "filter=groupType eq Vault&search=$GroupName&includeMembers=true"
    $GetGroupResult = FindCyberArkGroup -searchstring $SearchString -authZtoken $AuthZHeader
    
    if($GetGroupResult.count -eq 1){
        $members =  ($GetGroupResult.value.members | Select Username).Username -join ","
        $CyberArkGroups.Add([PSCustomObject]@{
                GroupName       = $_.GroupName
                Description     = $GetGroupResult.value.description
                Id              = $GetGroupResult.value.id
                groupType       = $GetGroupResult.value.groupType
                members         = $members
            }
        )
    }else{
        LogMessage -message "Group $GroupName does not exist."
    }
    
}

$CyberArkGroups | Export-Csv -Path $path -NoTypeInformation
#endregion
#region Logoff vault
#Logoff -authZtoken $AuthZHeader
#endregion