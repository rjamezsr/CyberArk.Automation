. .\Common.ps1
Function Create-FilterExpression {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $filters,
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        Position = 0)]
        [ValidateScript({ Test-Path -Path $_})]
        [string]
        $RegularExpressionFileFolder="",
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [switch]
        $any
    )
    process {
        $filtervalues = [System.Collections.ArrayList]@()
        $operator = "-and"
        if($any){
            $operator = "-or"
        }
        try {
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
            $filterexpressions = $filtervalues -join " $operator "
            [scriptblock]::Create($filterexpressions)
        } catch {
            LogMessage -message $Error[0]
            $null
        }
        
        
        

    }
}
