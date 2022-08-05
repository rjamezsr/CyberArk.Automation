[CmdletBinding()]
param ()
. .\Common.Connect.ps1

##############################################################
# OPTION 1: Connect via CCP provided service account
##############################################################
# Get Config. This configuration defines authentication flow for REST access. 
#  In this case, we'll use a config that defines CCP as the credential provider, 
#  in addition to the credential identification. 
#
#  THIS SETUP only requires that the AppID be passed. 
#
##############################################################
    Write-Output "***************"
    Write-Output "OPTION 1 - CCP Provided account"
    Write-Output "***************"

    $config = Get-Content -Path C:\repo\Azure.DevOps\Prolab-IDM\CyberArk.Automation.Config\VaultAuthorization.CCP.json | ConvertFrom-Json

    # Retrieve Service Credential. This credential has access to the safe we need. To get it, we'll call Secr Manager.  
    $credential = Get-ConnectCredentialViaApp -config $config

    # Logon useing the Service Credential. Here we are taking advantage of PSPAS module.
    New-PASSession -Credential $credential -BaseURI https://cyberark.cxcorp.local

    # Call a method using PSPAS. Note, already logged in using Service Account
    $numOfAccounts = (Get-PASAccount | Measure-Object).Count
    Write-Output "$numOfAccounts returned!"

    # Close session
    Close-PASSession


# OPTION 2: Connect via CCP provided service account with Certificate AuthN enforced
##############################################################
# Get Config. This configuration defines authentication flow for REST access. 
#  In this case, we'll use a config that defines CCP as the credential provider, 
#  in addition to the credential identification. 
#
#  THIS SETUP requires Certificate-based Authentication via script. 
#
##############################################################
    Write-Output "***************"
    Write-Output "OPTION 2 - CCP Provided account where Certificate-based authN is enforced"
    Write-Output "***************"
    $config = Get-Content -Path C:\repo\Azure.DevOps\Prolab-IDM\CyberArk.Automation.Config\VaultAuthorization.CCP.json | ConvertFrom-Json

    # Retrieve Service Credential. This credential has access to the safe we need. To get it, we'll call Secr Manager.  
    $credential = Get-ConnectCredentialViaApp -config $config

    # Logon useing the Service Credential. Here we are taking advantage of PSPAS module.
    New-PASSession -Credential $credential -BaseURI https://cyberark.cxcorp.local

    # Call a method using PSPAS. Note, already logged in using Service Account
    $numOfAccounts = (Get-PASAccount | Measure-Object).Count
    Write-Output "$numOfAccounts returned!"

    # Close session
    Close-PASSession

# OPTION 3: Connect via PACLI gateway account. 
##############################################################
# Get Config. This configuration defines authentication flow for PACLI access. 
#  In this case, we'll use a config that defines connection to vault using a gateway account, 
#  in addition to the credential identification. 
#
#  THIS SETUP retreives the service account credential via PACLI. 
#
##############################################################
    Write-Output "***************"
    Write-Output "OPTION 3 - PACLI Provided account where we are using a credential file created for a gateway account"
    Write-Output "***************"
    $config = Get-Content -Path C:\repo\Azure.DevOps\Prolab-IDM\CyberArk.Automation.Config\VaultAuthorization.json | ConvertFrom-Json

    # Retrieve Service Credential. This credential has access to the safe we need. To get it, we'll call Secr Manager.  
    $credential = Get-ConnectCredential -config $config.VaultAuthorization -reason "test"

    # Logon useing the Service Credential. Here we are taking advantage of PSPAS module.
    New-PASSession -Credential $credential -BaseURI https://cyberark.cxcorp.local

    # Call a method using PSPAS. Note, already logged in using Service Account
    $numOfAccounts = (Get-PASAccount | Measure-Object).Count
    Write-Output "$numOfAccounts returned!"

    # Close session
    Close-PASSession