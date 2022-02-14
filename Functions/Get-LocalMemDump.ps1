<#
Local Native memory dump
#>
Function Get-LocalMemDump {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Please Enter the FULL PATH of the destination for your dumpfile, including filename' )]$DestPath
    )

    $ss = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace Root\Microsoft\Windows\Storage
    Invoke-CimMethod -InputObject $ss -MethodName "GetDiagnosticInfo" -Arguments @{DestinationPath=$DestPath; IncludeLiveDump=$true}
}
