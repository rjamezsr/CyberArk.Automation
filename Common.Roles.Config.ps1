function Get-SafeRolePermissionsConfig {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $ConfigFile
    )
    process {
        LoadJSONConfig -configPath $ConfigFile
    }
}
function Get-SafeRoleConfig {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $RoleName,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $ConfigFile,
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        Position = 0)]
        [object]
        $configuration 
    )
    process {
        if($null -eq $configuration){
            $configuration = Get-SafeRolePermissionsConfig -ConfigFile $ConfigFile
        }
        try {
            $configuration.Roles | Where Name -eq $RoleName
        } catch {
            $error_msg = $Error[0]
            LogError -message $error_msg
            $null
        }
    }
}
function Get-DefaultPermissions {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $ConfigFile,
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        Position = 0)]
        [object]
        $configuration 
    )
    process {
        if($null -eq $configuration){
            $configuration = Get-SafeRolePermissionsConfig -ConfigFile $ConfigFile
        }
        try {
            $configuration.DefaultPermissions 
        } catch {
            $error_msg = $Error[0]
            LogError -message $error_msg
            $null
        }
    }
}
function Get-SafeRolePermissionOverrides {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $RoleName,
        
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        Position = 0)]
        [object]
        $configuration,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        Position = 0)]
        [object]
        $ConfigFile
    )
    process {
        if($null -eq $configuration){
            $configuration = Get-SafeRolePermissionsConfig -ConfigFile $ConfigFile
        }
        try {
            ($configuration.Roles | `
                Where Name -eq $RoleName | `
                Select PermissionOverrides).PermissionOverrides
        } catch {
            $error_msg = $Error[0]
            LogError -message $error_msg
            $null
        }
    }
}
function Get-SafeRolePermissions {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $RoleName,
        
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        Position = 0)]
        [object]
        $configuration,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        Position = 0)]
        [object]
        $ConfigFile
    )
    process {
        if($null -eq $configuration){
            $configuration = Get-SafeRolePermissionsConfig -ConfigFile $ConfigFile
        }
        try {
            $permissions = [System.Collections.ArrayList]@()
            $inheritRole = (Get-SafeRoleConfig -configuration $configuration -RoleName $RoleName).Inherit
            $defaults = Get-DefaultPermissions -configuration $configuration
            $overrides = Get-SafeRolePermissionOverrides -configuration $configuration -RoleName $RoleName
            
            if($null -eq $inheritRole){
                $defaults | Where Name -notin ($overrides | Select Name).Name | ForEach-Object {
                    [void]$permissions.Add($_)
                }
                $overrides | ForEach-Object {
                   [void]$permissions.Add($_)
                }
            }else{

                $inheritedPermissions = Get-SafeRolePermissions -configuration $configuration -RoleName $inheritRole
                $inheritedPermissions | Where Name -notin ($overrides | Select Name).Name | ForEach-Object {
                    [void]$permissions.Add($_)
                }
                $overrides | Where Name -notin ($permissions | Select Name).Name | ForEach-Object {
                    [void]$permissions.Add($_)
                }
                $defaults | Where Name -notin ($permissions | Select Name).Name | ForEach-Object {
                    [void]$permissions.Add($_)
                }

            }
            
            $permissions


        } catch {
            $error_msg = $Error[0]
            LogError -message $error_msg
            $null
        }
    }
}