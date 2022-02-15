<#
Find Services hidden using SDDL, which can be used for persistance
https://www.sans.org/blog/red-team-tactics-hiding-windows-services/
#>
Function Find-SDDLHiddenServices {
    #find services hidden using SDDL (some common legitimate hidden services are WUDFRd,WUDFWpdFs,WUDFWpdMtp)
    $SDDLServices = Compare-Object -ReferenceObject (Get-Service | Select-Object -ExpandProperty Name | % { $_ -replace "_[0-9a-f]{2,8}$" } ) -DifferenceObject (gci -path hklm:\system\currentcontrolset\services |
    % { $_.Name -Replace "HKEY_LOCAL_MACHINE\\","HKLM:\" } | ? { Get-ItemProperty -Path "$_" -name objectname -erroraction 'ignore' } | 
    % { $_.substring(40) }) -PassThru | ?{$_.sideIndicator -eq "=>"}

    foreach ($SDDLService in $SDDLServices)
    {
        Get-CimInstance -ClassName CIM_Service | where Name -EQ $SDDLService | fl *
    }

    
}
