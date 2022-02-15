<#
This will get the hash of the Service DLLs with the DLL Name/Path for active services
#>
Function Get-ActiveServiceDLLHashes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Please Enter the Algorithm you wish to use with -Algorithm' )]$Algorithm
    )

    Set-ItemProperty REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\*\* -ea 0 | where {($_.ServiceDll -ne $null)} | foreach {Get-FileHash -Algorithm $Algorithm $_.ServiceDll}
}
