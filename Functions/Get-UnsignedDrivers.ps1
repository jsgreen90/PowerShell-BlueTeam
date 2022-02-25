function Get-UnsignedDrivers {
    gci -path C:\Windows\System32\drivers -include *.sys -recurse -ea SilentlyContinue | Get-AuthenticodeSignature | where {$_.status -ne 'Valid'}
}
