<#
Find Drivers used by current processes that are unsigned
#>
Function Find-UnsignedDLLs {
    (gps).Modules.FileName | get-authenticodesignature | ? Status -NE "Valid"
}
