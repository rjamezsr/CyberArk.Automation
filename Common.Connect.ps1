. .\Common.ps1
$PSPAS_Session = $null
function Validate-GatewayConfig {
    [CmdletBinding()]
    [OutputType([boolean])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $config
    )
    process {
        $configErrors = [System.Collections.ArrayList]@()
        if($null -eq $config.gwuserobjectname -or $config.gwuserobjectname -eq ""){
            [void]$configErrors.Add("gwuserobjectname is missing or invalid")
        }
        if($null -eq $config.gwusersafe -or $config.gwusersafe -eq ""){
            [void]$configErrors.Add("gwusersafe is missing or invalid")
        }
        if($null -eq $config.gwuserfolder -or $config.gwuserfolder -eq ""){
            [void]$configErrors.Add("gwuserfolder is missing or invalid")
        }
        if($null -eq $config.user -or $config.user -eq ""){
            [void]$configErrors.Add("user is missing or invalid")
        }
        if($null -eq $config.gwuser -or $config.gwuser -eq ""){
            [void]$configErrors.Add("gwuser is missing or invalid")
        }
        if($null -eq $config.logonfile -or $config.logonfile -eq ""){
            [void]$configErrors.Add("logonfile is missing or invalid")
        }
        if($null -eq $config.vaultname -or $config.vaultname -eq ""){
            [void]$configErrors.Add("vaultname is missing or invalid")
        }
        if($null -eq $config.vaultip -or $config.vaultip -eq ""){
            [void]$configErrors.Add("vaultip is missing or invalid")
        }
        if($null -eq $config.pacliexe -or $config.pacliexe -eq ""){
            [void]$configErrors.Add("pacliexe is missing or invalid")
        }
        if($null -eq $config.sessionid -or $config.sessionid -eq ""){
            [void]$configErrors.Add("sessionid is missing or invalid")
        }
        if($configErrors.Count -ne 0){
            $errors = $configErrors -join ","
            LogMessage "VaultAuthorization is not valid: $errors"
        }
        $configErrors.Count -eq 0

    }
    
}
function Get-ConnectCredentialViaApp {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $config
    )
    process {
        $passCertificate = $false
        if($null -ne $config.VaultAuthorization.Application.CertificateFile -and $config.VaultAuthorization.Application.CertificateFile -ne ""){
            $Certificate = Get-Certificate -config $config.VaultAuthorization
            $passCertificate = $true
        }
        
        $secretId = $config.VaultAuthorization.Application.SecretID -f $config.VaultAuthorization.Application.AppID, `
            $config.VaultAuthorization.Application.SafeName, `
            $config.VaultAuthorization.Application.Folder, `
            $config.VaultAuthorization.Application.Name
        $url = "{0}://{1}" -f $config.VaultAuthorization.Application.BaseProtocol, $config.VaultAuthorization.Application.BaseURL
        try {
            if($passCertificate){
                $object = Invoke-RestMethod -Certificate $Certificate -Uri  ("{0}/AIMWebService/api/Accounts?{1}" -f $url,$secretId)
            }else{
                $object = Invoke-RestMethod -Uri  ("{0}/AIMWebService/api/Accounts?{1}" -f $url,$secretId)
            }
            
            $securePassword = ConvertTo-SecureString $object.Content -AsPlainText -Force
            New-Object System.Management.Automation.PSCredential ($object.Username, $securePassword)
        }catch{
            $msg = $Error[0]
            LogMessage "Could not get credential. Error: $msg"
            $null
        }
        

    }
}

function Get-Certificate {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $config
    )
    process {
        $CertSecret = ConvertTo-SecureString ($config.Application.CertificateSecret) -AsPlainText -Force
        $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $Certificate.Import(($config.Application.CertificateFile),$CertSecret,'DefaultKeySet')
        $Certificate
    }
}
function Get-ConnectCredential {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $config,
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $reason,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [switch]
        $legacy
    )
    process {
        $gatewayCred = Get-CredentialViaGateway $config -reason $reason
        $cred = $null
        if($null -ne $gatewayCred){
            $appUsr = $config.user.Trim()
            if($legacy){
                $PwdC =  Get-ConnectSecret -credObject $gatewayCred -legacy
            }else{
                $PwdC =  Get-ConnectSecret -credObject $gatewayCred
            }
            
            $cred = New-Object System.Management.Automation.PSCredential ($appUsr, $PwdC)
        }
        $cred
    }
}
function Get-ConnectSecret {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $credObject,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [switch]
        $legacy
    )
    process {
        if($legacy){
            $AppPwdC = $credObject.Password
            ConvertTo-SecureString $AppPwdC[2] -AsPlainText -Force
        }else{
            $AppPwdC = $credObject.Password[1]
            $AppPwdC = $AppPwdC.Replace(" ","") 
            ConvertTo-SecureString $AppPwdC -AsPlainText -Force
        }
        
        
    }
}
function Get-CredentialViaGateway {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $config,
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $reason
    )
    process {
        $Executing = $MyInvocation.MyCommand.Name
        $currentUser = $env:UserName
        $appUserCred = $null
        if(Validate-GatewayConfig $config){
            $appUserCred = PoSHPACLI_GetPassword -vaultname $config.vaultname `
                -user $config.gwuser `
                -logonfile $config.logonfile `
                -sessionid $config.sessionid `
                -vaultip $config.vaultip `
                -pacliexe $config.pacliexe `
                -targetsafe $config.gwusersafe `
                -folder $config.gwuserfolder `
                -objectname $config.gwuserobjectname `
                -reason $reason -autoChangePassword $true
        }
        $appUserCred
    }
}
function Connect-PSPAS{
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [ValidateScript({Test-Path $_})]
        [string]
        $ConfigPath,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $reason
    )
    process {
        if($null -ne $PSPAS_Session){
            $PSPAS_Session
        }else{
            $config = Get-Content $ConfigPath | ConvertFrom-Json
            $credential = Get-ConnectCredential -config $config.VaultAuthorization -reason $reason
            if($config.RESTAPI.DisableSSLVerify -eq "true"){
                New-PASSession -Credential $credential -BaseURI $config.RESTAPI.BaseURI -SkipCertificateCheck    
            }else{
                New-PASSession -Credential $credential -BaseURI $config.RESTAPI.BaseURI 
            }
            $PSPAS_Session = $true
            $PSPAS_Session
            
        }
    }
}
function Disconnect-PSPAS{
    [CmdletBinding()]
    [OutputType([object])]
    param ()
    process {
        if($null -ne $PSPAS_Session){
            Close-PASSession
            $PSPAS_Session = $null
        }
        $PSPAS_Session
    }
}
