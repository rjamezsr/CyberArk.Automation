. .\Common.ps1
. .\Common.Connect.ps1
$Session = $null
function Get-UserDetails {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [ValidateScript({Test-Path $_})]
        [string]
        $ConfigPath,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string]
        $id
    )
    process {
        $userObject = $null
        if($null -ne (Connect-PSPAS -ConfigPath $ConfigPath)){
            $user = Get-PASUser -id $id
            $userObject = [pscustomobject]@{
                Username=$user.username;
                Email=$user.internet.businessEmail;
            }
            Disconnect-PSPAS
        }
        $userObject
    }
}
function Get-UsersByGroup {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [ValidateScript({Test-Path $_})]
        [string]
        $ConfigPath,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string]
        $groupname
    )
    process {
        $members = [System.Collections.ArrayList]@()
        if($null -ne (Connect-PSPAS -ConfigPath $ConfigPath)){
            $groupObject = Get-PASGroup -search $groupname -includeMembers $true
            $groupObject.members | Foreach-Object {
                $username = $_.UserName
                $uid  =$_.id
                $uobj = Get-UserDetails -ConfigPath $ConfigPath -id $uid
                [void]$members.Add($uobj)

            }
            Disconnect-PSPAS
        }
        $members
    }
}
