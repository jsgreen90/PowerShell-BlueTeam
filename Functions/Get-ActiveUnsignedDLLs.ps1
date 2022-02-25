<#
Find Drivers used by current processes that are unsigned
#>
Function Get-ActiveUnsignedDLLs {
    (gps).Modules.FileName | get-authenticodesignature | ? Status -NE "Valid"
    #$A=$(foreach ($dll in gps|select -ExpandProperty modules -ea SilentlyContinue){Get-AuthenticodeSignature $dll.FileName |Where-Object Status -NE "Valid"|Select Path});
    #$B=$(foreach ($dll in $A){Get-FileHash $dll.Path| select Hash -ExpandProperty Hash})|Sort-Object| Get-Unique;
    #$B
}
