. '.\Common.ps1'
. '.\Common.Connect.ps1'
function Request-Account {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [ValidateScript({Test-Path $_})]
        [string]
        $ConfigPath
    )

    process {
        $VaultConfig = (LoadJSONConfig -configpath $ConfigPath).VaultAuthorization
        $config = (LoadJSONConfig -configpath $ConfigPath)
        $requestIDs = [System.Collections.ArrayList]@()
        $credential = Get-ConnectCredential -config $VaultConfig

        New-PASSession -Credential $credential -BaseURI $config.RESTAPI.BaseURI

        $config.AccountIDs | Foreach-Object {
            $id = $_
            LogMessage -message "Requesting access to account ID $id"
            $result = New-PASRequest -AccountId $id -Reason $config.Reason
            [void]$requestIDs.Add($result.RequestId)
        }
        Close-PASSession
        $requestIDs
    }
}
function Confirm-Account {
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
        [object]
        $requestIDs
    )

    process {
        $rest = (LoadJSONConfig -configpath $ConfigPath).RESTAPI
        $config = (LoadJSONConfig -configpath $ConfigPath).Confirmation
        $confirm = $config.Enabled -eq "true"
        if($requestIDs.Count -gt 0 -and $confirm){
            $credential = Get-ConnectCredential -config $config.VaultAuthorization
            $approve = $config.Disposition -eq "Approve"
            New-PASSession -Credential $credential -BaseURI $rest.BaseURI
            $requestIDs | ForEach-Object {
                if($approve){
                    LogMessage -message "Approver request ID $_"
                    Approve-PASRequest -RequestId $_ -Reason $config.Confirmation.Reason
                }else{
                    LogMessage -message "Deny request ID $_"
                    Deny-PASRequest -RequestId $_ -Reason $config.Confirmation.Reason
                }        
            }
            Close-PASSession
            
        }
    }
}