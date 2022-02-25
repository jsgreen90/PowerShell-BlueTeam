function Get-TaskHashes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Please Enter the hashing algorithm you would like to use' )]$HashAlg
    )

    $a=((gci C:\windows\system32\tasks -Recurse | Select-String "<Command>" | select -exp Line).replace("<Command>","").trim("</Command>").replace("`"","").trim());
    foreach ($b in $a){Get-FileHash -Algorithm $HashAlg ([System.Environment]::ExpandEnvironmentVariables($b))}
}
