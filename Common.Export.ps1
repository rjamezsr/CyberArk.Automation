[CmdletBinding()]
param ()
. .\Common.ps1
. .\Common.Connect.ps1
. .\Common.Export.Object.ps1
$config = "C:\repo\Azure.DevOps\Prolab-IDM\CyberArk.Automation.Config\Export.Config.json"
Accept-AllSSL
Connect-PSPAS -config $config -reason "Export User Data"
$data = Get-PASUser | Where-Object {$_.Id -eq 2}
$configData = Get-Content $config | ConvertFrom-Json
# $exportConfig = ($configData.Export.Objects | `
#     Where-Object {$_.Type -eq "User"}).Methods | `
#     Where-Object {$_.Type -eq "Extract"} 

# $objects = Get-ExportObjects -config $exportConfig -data $data
# $objects | Format-Table



($configData.Export.Objects | `
    Where-Object {$_.Type -eq "User"}).Methods | `
    Where-Object {$_.Type -eq "Extract"} | ForEach-Object {
        $exportConfig = $_
        $objects = Get-ExportObjects -config $exportConfig -data $data
        $objects | Format-Table    
    }


