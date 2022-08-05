$PATH_GLOBAL_CONFIG="Global.Config.JSON"
function Load-Config {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $Path
    )
    process {
        $ConfigDataJSON = $null
        try {
            $ConfigData     = Get-Content -Path $PATH 
            $ConfigDataJSON = $ConfigData | ConvertFrom-Json 
        }
        catch  {
            $message = $_.Exception
            Log-Message -message $message -error
        }
        $ConfigDataJSON 
    }
    
}
function Validate-Config {

}