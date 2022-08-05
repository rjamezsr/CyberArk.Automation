. '.\Common.Logging.ps1'
function Format-ExportValue {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $config,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $data
    )
    process {
        switch ($config.Format){
            "String" {
                $data
            }
            "ArrayOfString" {
                $data -join ","
            }
            "ArrayOfObject" {
                #TODO 
                # $key = $config.Key
                # $keyObject = $parent.$key
                # $arrayOfObject = Transform-Object -config $config -data $data
                # $arrayOfObject.Add([pscustomobject]@{Name=$config.Key;Value=$keyObject})

                # $arrayOfObject
                $data
            }
            default {
                $data
            }
        }
    }
}
function Transpose-NameValuePair {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $list
    )
    process {
        $transposed = [pscustomobject]@{}
        $list | ForEach-Object {
            $transposedObjectName = $_.Name
            $transposedObject = $transposed.$transposedObjectName
            if($null -eq $transposedObject){
                $transposed | Add-Member -MemberType NoteProperty -Name $_.Name -Value $_.Value
            }else{
                $transposed.$transposedObjectName = $_.Value
            }
        }
        $transposed
    }
}

function Create-Mapobject {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $obj,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $name
    )
    process {
        $obj.$name
    }
}
function Transform-Object {
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]
    param (
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $config,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $data
    )
    process {
        
        $members = [System.Collections.ArrayList]@()
        $config.Mapping | Foreach-Object {
            $memberobj = $null
            $path = $_.Path -split "/"
            $path | Foreach-Object {
                if($null -eq $memberobj){
                    $memberobj = Create-Mapobject -obj $data -name $_
                }else{
                    $data = $memberobj
                    $memberobj = Create-Mapobject -obj $data -name $_
                }
    
            }
            $value = Format-ExportValue -config $_ -data $memberobj 
            if($_.Format -eq "ArrayOfObject"){
                #$key = $_.Key
                #$keyValue = $data.$key
                $childConfig = $_
                $value | Foreach-Object {
                    $child = Transform-Object -config $childConfig -data $_
                    [void]$members.Add([PSCustomObject]@{
                        Name = $child.Name;Value=$child.Value
                    })
                }
                <#
                [void]$members.Add([PSCustomObject]@{
                    Name = $key;Value=$keyValue
                })
                #>
            }else{
                [void]$members.Add([PSCustomObject]@{
                    Name = $_.TargetName;Value=$value
                })
            }
            
        }
        $members
    }
}
function Get-ExportObjects {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $config,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $data
    )
    process {
        $objectData = [System.Collections.ArrayList]@()
        $data | Foreach-Object {
            $object = Get-ExportObject -config $config -data $_
            #[void]$objectData.Add($object)
            $record = Transpose-NameValuePair -list $object
            [void]$objectData.Add($record)
        }
        $objectData
    }
    
}
function Get-ExportObject {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $config,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $data
    )
    
    process {
        Create-ExportObject -config $config -data $data
    }
}
function Create-ExportObject {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $config,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $data
    )
    
    process {

        
        $dataobject = Create-DataObject -config $config -data $data 
        Transform-Object -config $config -data $dataobject
        
    }
}
function Create-DataObject {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $config,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $data
    )
    
    process {
        try {
            $method = $config.MethodName
            $parameters = [System.Collections.ArrayList]@()
            $pmembers= $config.Parameters | Measure-Object
            if($pmembers.Count -gt 0){
                $config.Parameters | Foreach-Object {
                    $pName = $_.Name
                    $pValue = $_.Value
                    $pSource = $_.ValueSource
                    switch ($pSource) {
                        "[DATA]" {
                            $rawValue = $data.$pValue
                        }
                        default {
                            $rawValue = $data.$pValue
                        }
                    }
                    [void]$parameters.Add("-" + $_.Name + " " + $rawValue)
                }
                $method = $method + " " + ($parameters -join " ")
            }
            Invoke-Expression $method
        } catch {
            Log-Message -error -message $Error[0]
            $null
        }
        
    }
}