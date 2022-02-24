<#
Find Drivers used by current processes that are unsigned
#>
Function Get-ActiveUnsignedDLLs {
    (gps).Modules.FileName | get-authenticodesignature | ? Status -NE "Valid"
}
